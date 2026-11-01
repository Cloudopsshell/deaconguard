package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/notify"
	"deaconguard/internal/schedule"
	"deaconguard/internal/store"
)

// metaDashboardURL is the dashboard's address, for links in notifications.
const metaDashboardURL = "dashboard_url"

// deliveryRetries are the waits before each retry of a failed delivery;
// after the last, it fails for good.
var deliveryRetries = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

// notifier sends queued notifications in the background.
type notifier struct {
	wake   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex // one delivery pass at a time
}

func (s *Server) startNotifier() {
	ctx, cancel := context.WithCancel(context.Background())
	s.notifier.cancel = cancel
	s.notifier.wg.Add(1)
	go func() {
		defer s.notifier.wg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			s.deliverDue(ctx, time.Now())
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-s.notifier.wake:
			}
		}
	}()
}

func (s *Server) stopNotifier() {
	if s.notifier.cancel != nil {
		s.notifier.cancel()
		s.notifier.wg.Wait()
	}
}

// stored is a queued message as saved: the message and its attachment.
type stored struct {
	Message    notify.Message `json:"message"`
	Attachment *struct {
		Name        string `json:"name"`
		ContentType string `json:"content_type"`
		Data        []byte `json:"data"`
	} `json:"attachment,omitempty"`
}

func encodeMessage(message notify.Message) (string, error) {
	record := stored{Message: message}
	if attachment := message.Attachment; attachment != nil {
		record.Attachment = &struct {
			Name        string `json:"name"`
			ContentType string `json:"content_type"`
			Data        []byte `json:"data"`
		}{attachment.Name, attachment.ContentType, attachment.Data}
	}
	encoded, err := json.Marshal(record)
	return string(encoded), err
}

func decodeMessage(text string) (notify.Message, error) {
	var record stored
	if err := json.Unmarshal([]byte(text), &record); err != nil {
		return notify.Message{}, err
	}
	if record.Attachment != nil {
		record.Message.Attachment = &notify.Attachment{Name: record.Attachment.Name, ContentType: record.Attachment.ContentType, Data: record.Attachment.Data}
	}
	return record.Message, nil
}

// link is a dashboard address for path, or "" when the dashboard's address
// isn't set.
func link(path string) string {
	base, err := store.Meta(metaDashboardURL)
	if err != nil || base == "" {
		return ""
	}
	return strings.TrimSuffix(base, "/") + path
}

// emit queues message for every enabled channel subscribed to its event
// and, for a host's event, whose tags (if any) the host has.
func (s *Server) emit(message notify.Message) {
	channels, err := store.Channels()
	if err != nil {
		serverLog("", store.LogError, "Could not read the notification channels: %v", err)
		return
	}
	var hostTags []string
	if message.HostID != "" {
		hostTags, _ = store.HostTags(message.HostID)
		if window, inWindow, err := store.InMaintenance(hostTags, time.Now()); err == nil && inWindow && message.Event != notify.EventTest {
			serverLog(message.HostID, store.LogInfo, "Held back a notification during the maintenance window %q: %s", window.Name, message.Title)
			return
		}
	}
	if message.At.IsZero() {
		message.At = time.Now().UTC()
	}
	queued := false
	for _, channel := range channels {
		if !channel.Enabled || !slices.Contains(channel.Events, message.Event) {
			continue
		}
		if len(message.Channels) > 0 && !slices.Contains(message.Channels, channel.ID) {
			continue
		}
		if message.HostID != "" && len(channel.Tags) > 0 && !slices.ContainsFunc(channel.Tags, func(tag string) bool { return slices.Contains(hostTags, tag) }) {
			continue
		}
		if s.enqueue(channel, message) == nil {
			queued = true
		}
	}
	if queued {
		s.wakeNotifier()
	}
}

func (s *Server) enqueue(channel store.Channel, message notify.Message) error {
	encoded, err := encodeMessage(message)
	if err == nil {
		_, err = store.EnqueueDelivery(channel.ID, message.Event, message.Title, encoded)
	}
	if err != nil {
		serverLog("", store.LogError, "Could not queue a notification for %q: %v", channel.Name, err)
	}
	return err
}

func (s *Server) wakeNotifier() {
	select {
	case s.notifier.wake <- struct{}{}:
	default:
	}
}

// deliverDue sends the queued notifications that are due, retrying failures
// after deliveryRetries.
func (s *Server) deliverDue(ctx context.Context, now time.Time) {
	s.notifier.mu.Lock()
	defer s.notifier.mu.Unlock()
	due, err := store.DueDeliveries(now, 50)
	if err != nil {
		serverLog("", store.LogError, "Could not read the notifications to send: %v", err)
		return
	}
	for _, delivery := range due {
		if ctx.Err() != nil {
			return
		}
		sendErr := deliver(ctx, delivery)
		retry := time.Time{}
		if sendErr != nil && delivery.Attempts < len(deliveryRetries) && !errors.Is(sendErr, errChannelGone) {
			retry = now.Add(deliveryRetries[delivery.Attempts])
		}
		if err := store.DeliveryAttempted(delivery.ID, sendErr, retry); err != nil {
			serverLog("", store.LogError, "Could not record a notification: %v", err)
		}
		if sendErr != nil && retry.IsZero() {
			serverLog("", store.LogWarning, "Could not send the notification %q: %v", delivery.Title, sendErr)
		}
	}
}

var errChannelGone = errors.New("the channel was turned off or removed")

func deliver(ctx context.Context, delivery store.Delivery) error {
	channel, err := store.GetChannel(delivery.ChannelID)
	if err != nil || (!channel.Enabled && delivery.Event != notify.EventTest) {
		return errChannelGone
	}
	var config notify.Config
	if err := json.Unmarshal([]byte(channel.Config), &config); err != nil {
		return fmt.Errorf("read the channel's settings: %w", err)
	}
	message, err := decodeMessage(delivery.Message)
	if err != nil {
		return fmt.Errorf("read the message: %w", err)
	}
	return notify.Send(ctx, channel.Kind, config, message)
}

// scanFinished turns a finished scan into notifications: a failure; new
// vulnerabilities known to be exploited or critical ones with a fix, on the
// host or in its running containers; new cluster or configuration findings;
// malware; changed system files; an audit's grade; and, for channels that
// want every scan, a summary.
func (s *Server) scanFinished(host store.Host, scanID string, failure error) {
	hostLink := link("/hosts/" + host.ID)
	if failure != nil {
		s.emit(notify.Message{Event: notify.EventScanFailed, Level: notify.LevelWarning, Title: host.Address + ": scan failed",
			Lines: []string{failure.Error(), "A failed scan is not a clean result; the host's earlier results stand."},
			Link:  hostLink, HostID: host.ID, Host: host.Address, ScanID: scanID, Data: map[string]any{"error": failure.Error()}})
		return
	}
	record, err := store.GetScan(scanID)
	if err != nil {
		return
	}
	scanLink := link("/scans/" + scanID)
	if slices.Contains(record.Checks, store.CheckPackages) {
		s.newVulnerabilities(host, record, scanLink)
	}
	if slices.Contains(record.Checks, checks.Containers) {
		s.newContainerVulnerabilities(host, record, scanLink)
	}
	if slices.Contains(record.Checks, checks.Kubernetes) {
		s.newFindings(host, record, scanLink, checks.Kubernetes, notify.EventCluster, "HIGH", "new critical or high finding", "new critical or high findings")
	}
	if slices.Contains(record.Checks, checks.Config) {
		s.newFindings(host, record, scanLink, checks.Config, notify.EventConfig, "MEDIUM", "new configuration finding", "new configuration findings")
	}
	if slices.Contains(record.Checks, checks.Changes) {
		s.newFindings(host, record, scanLink, checks.Changes, notify.EventChanges, "MEDIUM", "change since the previous scan", "changes since the previous scan")
	}
	if slices.Contains(record.Checks, checks.Paths) {
		s.newFindings(host, record, scanLink, checks.Paths, notify.EventPaths, "HIGH", "new attack path or exposed secret", "new attack paths or exposed secrets")
	}
	counts, err := store.ScanCheckCounts(scanID)
	if err != nil {
		serverLog(host.ID, store.LogError, "Could not read the results of the scan of %s for notifications: %v", host.Address, err)
		return
	}
	malware := counts[checks.Malware].Findings + counts[checks.Antivirus].Findings + counts[checks.YARA].Findings
	if malware > 0 {
		lines := []string{"Look at the scan now; treat the host as compromised until you know otherwise."}
		data := map[string]any{"findings": malware}
		if names := malwareContainers(scanID); len(names) > 0 {
			shown := names
			if len(shown) > 5 {
				shown = shown[:5]
			}
			line := "In " + plural(len(names), "container", "containers") + ": " + strings.Join(shown, ", ")
			if len(names) > len(shown) {
				line += fmt.Sprintf(" and %d more", len(names)-len(shown))
			}
			lines = append(lines, line+".")
			data["containers"] = names
		}
		s.emit(notify.Message{Event: notify.EventMalware, Level: notify.LevelCritical,
			Title: fmt.Sprintf("%s: malware or signs of compromise found (%s)", host.Address, plural(malware, "finding", "findings")),
			Lines: lines, Link: scanLink, HostID: host.ID, Host: host.Address, ScanID: scanID, Data: data})
	}
	if changed := counts[checks.Integrity].Severe; changed > 0 {
		s.emit(notify.Message{Event: notify.EventIntegrity, Level: notify.LevelCritical,
			Title: fmt.Sprintf("%s: %s from what %s installed", host.Address, plural(changed, "system file differs", "system files differ"), pick(changed, "its package", "their packages")),
			Lines: []string{"Changed binaries and libraries are a classic sign of a rootkit, unless someone changed them on purpose."},
			Link:  scanLink, HostID: host.ID, Host: host.Address, ScanID: scanID, Data: map[string]any{"files": changed}})
	}
	if record.Audit {
		s.auditFinished(host, record)
	}
	s.scanResults(host, record, scanLink)
}

// newVulnerabilities notifies about known exploited vulnerabilities, and
// critical ones with a fix, that the host's previous scan didn't have.
func (s *Server) newVulnerabilities(host store.Host, record store.Scan, scanLink string) {
	previous, found, err := store.PreviousPackageScan(record)
	if err != nil {
		return
	}
	newCVEs := func(kind string) []string {
		current, err := store.ScanCVEs(record.ID, kind)
		if err != nil {
			return nil
		}
		before := map[string]bool{}
		if found {
			before, _ = store.ScanCVEs(previous.ID, kind)
		}
		var added []string
		for cve := range current {
			if !before[cve] {
				added = append(added, cve)
			}
		}
		sort.Strings(added)
		return added
	}
	if added := newCVEs(store.CVEsExploited); len(added) > 0 {
		lines := []string{listCVEs(added), "In CISA's Known Exploited Vulnerabilities catalog: attackers use them. Fix these first."}
		if record.Exploit.KnownFixable > 0 {
			lines = append(lines, fmt.Sprintf("%s on this host %s a fix: install the updates.", plural(record.Exploit.KnownFixable, "known exploited vulnerability", "known exploited vulnerabilities"), pick(record.Exploit.KnownFixable, "has", "have")))
		}
		s.emit(notify.Message{Event: notify.EventExploited, Level: notify.LevelCritical,
			Title: fmt.Sprintf("%s: %s known to be exploited", host.Address, plural(len(added), "new vulnerability", "new vulnerabilities")),
			Lines: lines, Link: scanLink, HostID: host.ID, Host: host.Address, ScanID: record.ID, Data: map[string]any{"cves": added}})
	}
	if added := newCVEs(store.CVEsCriticalFixable); len(added) > 0 {
		s.emit(notify.Message{Event: notify.EventCritical, Level: notify.LevelWarning,
			Title: fmt.Sprintf("%s: %s with a fix", host.Address, plural(len(added), "new critical vulnerability", "new critical vulnerabilities")),
			Lines: []string{listCVEs(added), "Installing the updates fixes them."},
			Link:  scanLink, HostID: host.ID, Host: host.Address, ScanID: record.ID, Data: map[string]any{"cves": added}})
	}
}

// checkResult is one check's result in a scan, unless the check didn't run
// or failed.
// malwareContainers names the containers the malware checks found
// something in, in order.
func malwareContainers(scanID string) []string {
	var names []string
	seen := map[string]bool{}
	for _, check := range []string{checks.Malware, checks.Antivirus, checks.YARA} {
		result, ok := checkResult(scanID, check)
		if !ok {
			continue
		}
		for _, finding := range result.Findings {
			if finding.Container != "" && !seen[finding.Container] {
				seen[finding.Container] = true
				names = append(names, finding.Container)
			}
		}
	}
	return names
}

func checkResult(scanID, check string) (checks.Result, bool) {
	report, err := store.GetFullReport(scanID)
	if err != nil {
		return checks.Result{}, false
	}
	encoded, _ := json.Marshal(report["check_results"])
	var results map[string]checks.Result
	if json.Unmarshal(encoded, &results) != nil {
		return checks.Result{}, false
	}
	result, ok := results[check]
	if !ok || result.Status == checks.StatusFailed || result.Status == checks.StatusSkipped {
		return checks.Result{}, false
	}
	return result, true
}

// previousCheckResult is check's result in the newest successful scan of
// the host that ran it before record, if any.
func previousCheckResult(host store.Host, record store.Scan, check string) (checks.Result, bool) {
	scans, err := store.ListScans(host.ID, 50)
	if err != nil {
		return checks.Result{}, false
	}
	for _, earlier := range scans {
		if earlier.ID == record.ID || earlier.Status != store.ScanSucceeded || !slices.Contains(earlier.Checks, check) ||
			earlier.StartedAt > record.StartedAt {
			continue
		}
		if result, ok := checkResult(earlier.ID, check); ok {
			return result, true
		}
	}
	return checks.Result{}, false
}

// severityRank orders severities, most urgent first.
func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

// newFindings notifies about a check's findings at least as severe as
// worst that the host's previous run of the check didn't have, by rule and
// title, which name what they are about: a privileged workload deployed in
// a cluster, or SSH starting to accept passwords.
func (s *Server) newFindings(host store.Host, record store.Scan, scanLink, check, event, worst, noun, nouns string) {
	current, ok := checkResult(record.ID, check)
	if !ok {
		return
	}
	previous, _ := previousCheckResult(host, record, check)
	seen := map[string]bool{}
	for _, f := range previous.Findings {
		seen[f.Rule+"\x00"+f.Title] = true
	}
	var added []checks.Finding
	for _, f := range current.Findings {
		key := f.Rule + "\x00" + f.Title
		if severityRank(f.Severity) <= severityRank(worst) && !seen[key] {
			seen[key] = true
			added = append(added, f)
		}
	}
	if len(added) == 0 {
		return
	}
	sort.SliceStable(added, func(i, j int) bool {
		if rank := severityRank(added[i].Severity) - severityRank(added[j].Severity); rank != 0 {
			return rank < 0
		}
		return added[i].Title < added[j].Title
	})
	level := notify.LevelWarning
	if strings.EqualFold(added[0].Severity, "CRITICAL") {
		level = notify.LevelCritical
	}
	var lines, rules []string
	for index, f := range added {
		rules = append(rules, f.Rule)
		if index < 10 {
			lines = append(lines, strings.ToUpper(f.Severity)+": "+f.Title)
		}
	}
	if len(added) > 10 {
		lines = append(lines, fmt.Sprintf("… and %d more", len(added)-10))
	}
	s.emit(notify.Message{Event: event, Level: level,
		Title: fmt.Sprintf("%s: %s", host.Address, plural(len(added), noun, nouns)),
		Lines: lines, Link: scanLink, HostID: host.ID, Host: host.Address, ScanID: record.ID, Data: map[string]any{"rules": rules}})
}

// containerCVEs are the vulnerabilities in a containers check that want
// says to report, by image and CVE: a container started again from the same
// image has a new ID but the same vulnerabilities.
func containerCVEs(result checks.Result, want func(checks.Finding) bool) map[string]map[string]bool {
	found := map[string]map[string]bool{}
	for _, container := range result.Containers {
		if !container.Scanned() {
			continue
		}
		for _, f := range container.Findings {
			if !want(f) {
				continue
			}
			if found[container.Image] == nil {
				found[container.Image] = map[string]bool{}
			}
			found[container.Image][f.Rule] = true
		}
	}
	return found
}

// newContainerVulnerabilities notifies about vulnerabilities known to be
// exploited, and critical ones a rebuild fixes, in the host's running
// containers that its previous containers scan didn't have.
func (s *Server) newContainerVulnerabilities(host store.Host, record store.Scan, scanLink string) {
	current, ok := checkResult(record.ID, checks.Containers)
	if !ok {
		return
	}
	previous, _ := previousCheckResult(host, record, checks.Containers)
	report := func(event, level string, want func(checks.Finding) bool, one, many, advice string) {
		before := containerCVEs(previous, want)
		var images []string
		added := map[string][]string{}
		total := 0
		var all []string
		for image, cves := range containerCVEs(current, want) {
			for cve := range cves {
				if !before[image][cve] {
					added[image] = append(added[image], cve)
				}
			}
			if len(added[image]) > 0 {
				images = append(images, image)
				sort.Strings(added[image])
				total += len(added[image])
				all = append(all, added[image]...)
			}
		}
		if total == 0 {
			return
		}
		sort.Strings(images)
		var lines []string
		for index, image := range images {
			if index == 10 {
				lines = append(lines, fmt.Sprintf("… and %d more images", len(images)-10))
				break
			}
			lines = append(lines, image+": "+listCVEs(added[image]))
		}
		lines = append(lines, advice)
		slices.Sort(all)
		s.emit(notify.Message{Event: event, Level: level,
			Title: fmt.Sprintf("%s: %s in running containers", host.Address, plural(total, one, many)),
			Lines: lines, Link: scanLink, HostID: host.ID, Host: host.Address, ScanID: record.ID,
			Data: map[string]any{"cves": slices.Compact(all), "images": images}})
	}
	report(notify.EventExploited, notify.LevelCritical, func(f checks.Finding) bool { return f.Exploited },
		"new vulnerability known to be exploited", "new vulnerabilities known to be exploited",
		"In CISA's Known Exploited Vulnerabilities catalog: attackers use them. Rebuild these images, or update them, first.")
	report(notify.EventCritical, notify.LevelWarning, func(f checks.Finding) bool {
		return strings.EqualFold(f.Severity, "CRITICAL") && f.Fixable
	}, "new critical vulnerability with a fix", "new critical vulnerabilities with a fix", "Rebuilding the images with updated packages fixes them.")
}

// scanResults sums up a finished host scan in a line per check, for
// channels that want to hear about every scan.
func (s *Server) scanResults(host store.Host, record store.Scan, scanLink string) {
	counts, err := store.ScanCheckCounts(record.ID)
	if err != nil {
		return
	}
	names := map[string]string{}
	for _, definition := range checks.Definitions() {
		names[definition.ID] = definition.Name
	}
	var lines []string
	severe := 0
	for _, check := range record.Checks {
		name := names[check]
		if name == "" {
			name = check
		}
		count, ran := counts[check]
		switch {
		case !ran:
			lines = append(lines, name+": didn't run")
		case count.Findings == 0:
			lines = append(lines, name+": nothing found")
		case count.Severe > 0:
			severe += count.Severe
			lines = append(lines, fmt.Sprintf("%s: %s, %d critical or high", name, plural(count.Findings, "finding", "findings"), count.Severe))
		default:
			lines = append(lines, fmt.Sprintf("%s: %s", name, plural(count.Findings, "finding", "findings")))
		}
	}
	level := notify.LevelInfo
	if severe > 0 {
		level = notify.LevelWarning
	}
	what := "scan"
	if record.Audit {
		what = "audit"
	}
	title := fmt.Sprintf("%s: %s finished", host.Address, what)
	if started, err := time.Parse(time.RFC3339, record.StartedAt); err == nil && record.FinishedAt != nil {
		if finished, err := time.Parse(time.RFC3339, *record.FinishedAt); err == nil {
			if took := finished.Sub(started).Round(time.Second); took > 0 {
				title += " in " + took.String()
			}
		}
	}
	s.emit(notify.Message{Event: notify.EventScanResults, Level: level, Title: title,
		Lines: lines, Link: scanLink, HostID: host.ID, Host: host.Address, ScanID: record.ID,
		Data: map[string]any{"checks": record.Checks, "critical_or_high": severe}})
}

func (s *Server) auditFinished(host store.Host, record store.Scan) {
	summary, err := gradeAudit(record)
	if err != nil {
		return
	}
	level := notify.LevelInfo
	if summary.Grade == "D" || summary.Grade == "F" {
		level = notify.LevelWarning
	}
	lines := []string{fmt.Sprintf("%d of %d controls passed.", summary.Counts.Passed, summary.Counts.Passed+summary.Counts.Failed)}
	for _, reason := range summary.Caps {
		lines = append(lines, "Holds the grade back: "+reason)
	}
	s.emit(notify.Message{Event: notify.EventAudit, Level: level,
		Title: fmt.Sprintf("%s: audit finished, grade %s (%d)", host.Address, summary.Grade, summary.Score),
		Lines: lines, Link: link("/audits/" + record.ID), HostID: host.ID, Host: host.Address, ScanID: record.ID,
		Data: map[string]any{"grade": summary.Grade, "score": summary.Score}})
}

// agentQuiet notifies that an agent stopped checking in.
func (s *Server) agentQuiet(hostID, address string, lastSeen time.Time) {
	s.emit(notify.Message{Event: notify.EventAgentOffline, Level: notify.LevelWarning,
		Title: address + ": the agent stopped checking in",
		Lines: []string{"Last seen " + lastSeen.UTC().Format("2006-01-02 15:04 UTC") + ". Scans wait for it to come back. On the machine: sudo systemctl status deaconguard-agent"},
		Link:  link("/hosts/" + hostID), HostID: hostID, Host: address, Data: map[string]any{"last_seen": lastSeen.UTC().Format(time.RFC3339)}})
}

func listCVEs(cves []string) string {
	if len(cves) > 10 {
		return strings.Join(cves[:10], ", ") + fmt.Sprintf(" and %d more", len(cves)-10)
	}
	return strings.Join(cves, ", ")
}

func plural(count int, one, many string) string {
	if count == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", count, many)
}

func pick(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

// sendDueDigests queues the daily and weekly digests that are due.
func (s *Server) sendDueDigests(now time.Time) {
	due, err := store.DueDigests(now)
	if err != nil {
		serverLog("", store.LogError, "Could not read the notification digests: %v", err)
		return
	}
	for _, channel := range due {
		next := ""
		if at, err := digestWhen(channel).Next(now); err == nil {
			next = at.UTC().Format(time.RFC3339)
		}
		// Record the run first, so a failure never sends it every tick.
		if err := store.SetNextDigest(channel.ID, next); err != nil {
			continue
		}
		message, err := digest(channel)
		if err != nil {
			serverLog("", store.LogError, "Could not make the digest for %q: %v", channel.Name, err)
			continue
		}
		if s.enqueue(channel, message) == nil {
			s.wakeNotifier()
		}
	}
}

func digestWhen(channel store.Channel) schedule.When {
	days := channel.DigestDays
	if channel.Digest == "daily" {
		days = []int{0, 1, 2, 3, 4, 5, 6}
	}
	return schedule.When{Days: days, Time: channel.DigestTime, Timezone: channel.Timezone}
}

// digest sums up every host's latest results, limited to the channel's
// tags, with the open vulnerabilities as a CSV file for email.
func digest(channel store.Channel) (notify.Message, error) {
	result, err := buildSummary()
	if err != nil {
		return notify.Message{}, err
	}
	findings, err := store.LatestFindings()
	if err != nil {
		return notify.Message{}, err
	}
	inScope := func(tags []string) bool {
		return len(channel.Tags) == 0 || slices.ContainsFunc(channel.Tags, func(tag string) bool { return slices.Contains(tags, tag) })
	}
	hosts, scanned, failed, stale := 0, 0, 0, 0
	var severity store.SeverityCounts
	known, knownFixable, likely := 0, 0, 0
	var containers containerTotals
	tagged := map[string]bool{}
	for _, host := range result.HostSummaries {
		if !inScope(host.Tags) {
			continue
		}
		hosts++
		tagged[host.ID] = true
		if latest, ok := host.Checks[checks.Containers]; ok {
			containers.add(latest.ScanID)
		}
		if host.LastScan != nil && host.LastScan.Status == store.ScanFailed {
			failed++
		}
		report := host.LastReport
		if report == nil {
			continue
		}
		scanned++
		if started, err := time.Parse(time.RFC3339, report.StartedAt); err == nil && time.Since(started) > staleAfter {
			stale++
		}
		if report.Fixes != nil {
			severity.Critical += report.Fixes.Actionable.Critical
			severity.High += report.Fixes.Actionable.High
			severity.Medium += report.Fixes.Actionable.Medium
			severity.Low += report.Fixes.Actionable.Low
		}
		known += report.Exploit.Known
		knownFixable += report.Exploit.KnownFixable
		likely += report.Exploit.Likely
	}
	period := "Daily"
	if channel.Digest == "weekly" {
		period = "Weekly"
	}
	scope := "all hosts"
	if len(channel.Tags) > 0 {
		scope = "hosts tagged " + strings.Join(channel.Tags, " or ")
	}
	level := notify.LevelInfo
	if known > 0 || severity.Critical > 0 {
		level = notify.LevelWarning
	}
	lines := []string{
		fmt.Sprintf("%d of %d hosts have results; %d not scanned in the last 7 days; %d whose last scan failed.", scanned, hosts, stale, failed),
		fmt.Sprintf("To fix now: %d critical, %d high, %d medium, %d low.", severity.Critical, severity.High, severity.Medium, severity.Low),
		fmt.Sprintf("Known exploited (CISA KEV): %d, %d of them with a fix. Likely exploited (EPSS 10%% or more): %d.", known, knownFixable, likely),
	}
	if containers.Images > 0 {
		lines = append(lines, fmt.Sprintf("Running containers: %s on %s; %d known exploited, %d critical with a fix in the image.",
			plural(containers.Images, "image", "images"), plural(containers.Hosts, "host", "hosts"), containers.Exploited, containers.CriticalFixable))
		if containers.Exploited > 0 {
			level = notify.LevelWarning
		}
	}
	if sla, err := store.GetSLA(); err == nil && sla.Enabled {
		overdue, overdueHosts := map[string]bool{}, map[string]bool{}
		for _, finding := range findings {
			if tagged[finding.HostID] && finding.Overdue {
				overdue[finding.HostID+" "+finding.CVE] = true
				overdueHosts[finding.HostID] = true
			}
		}
		lines = append(lines, fmt.Sprintf("Past their fix deadline: %d, on %d hosts.", len(overdue), len(overdueHosts)))
	}
	var top []string
	for _, vulnerability := range result.TopVulnerability {
		if vulnerability.KEV && len(top) < 5 {
			top = append(top, vulnerability.CVE+" ("+strings.Join(vulnerability.Packages, ", ")+")")
		}
	}
	if len(top) > 0 && len(channel.Tags) == 0 {
		lines = append(lines, "Known exploited, first to fix: "+strings.Join(top, "; "))
	}
	// The open vulnerabilities, one row per host and package, for email.
	var table bytes.Buffer
	writer := csv.NewWriter(&table)
	_ = writer.Write([]string{"Host", "CVE", "Package", "Installed", "Fixed in", "What clears it", "Severity", "CVSS", "EPSS", "Known exploited"})
	rows := 0
	for _, finding := range findings {
		if !tagged[finding.HostID] {
			continue
		}
		epss, cvss, kev := "", "", ""
		if finding.EPSS != nil {
			epss = fmt.Sprintf("%.4f", *finding.EPSS)
		}
		if finding.CVSSScore > 0 {
			cvss = fmt.Sprintf("%.1f", finding.CVSSScore)
		}
		if finding.KEV {
			kev = "yes, due " + finding.KEVDue
		}
		_ = writer.Write(safeCells([]string{finding.Address, finding.CVE, finding.Package, finding.InstalledVersion, finding.FixedVersion, finding.Fix, finding.Severity, cvss, epss, kev}))
		rows++
	}
	writer.Flush()
	now := time.Now().UTC()
	message := notify.Message{Event: notify.EventDigest, Level: level, Title: fmt.Sprintf("%s summary of %s", period, scope), Lines: lines,
		Link: link("/"), At: now,
		Data: map[string]any{"hosts": hosts, "scanned": scanned, "stale": stale, "failed": failed, "to_fix": severity,
			"known_exploited": known, "known_exploited_fixable": knownFixable, "likely_exploited": likely, "containers": containers}}
	// Only email carries files.
	if channel.Kind == notify.Email {
		message.Lines = append(message.Lines, fmt.Sprintf("Attached: every open vulnerability (%d rows), as CSV.", rows))
		message.Attachment = &notify.Attachment{Name: "deaconguard-vulnerabilities-" + now.Format("2006-01-02") + ".csv", ContentType: "text/csv", Data: table.Bytes()}
	}
	return message, nil
}

// containerTotals sums the running containers in hosts' latest containers
// scans: each image once per host, however many containers run it.
type containerTotals struct {
	Hosts           int `json:"hosts"`
	Images          int `json:"images"`
	Exploited       int `json:"known_exploited"`
	CriticalFixable int `json:"critical_fixable"`
}

func (t *containerTotals) add(scanID string) {
	result, ok := checkResult(scanID, checks.Containers)
	if !ok {
		return
	}
	images := map[string]bool{}
	for _, container := range result.Containers {
		if !container.Scanned() || images[container.Image] {
			continue
		}
		images[container.Image] = true
		t.Exploited += container.Exploited
		t.CriticalFixable += container.FixableSeverity["CRITICAL"]
	}
	if len(images) > 0 {
		t.Hosts++
		t.Images += len(images)
	}
}

// safeCells keeps spreadsheet tools from reading cells as formulas, since
// package names and versions come from the scanned machine.
func safeCells(cells []string) []string {
	for index, cell := range cells {
		if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
			cells[index] = "'" + cell
		}
	}
	return cells
}

// The API.

type channelView struct {
	store.Channel
	Config notify.Config `json:"config"`
	// Last is the channel's latest delivery, if any.
	Last *store.Delivery `json:"last,omitempty"`
}

func viewChannel(channel store.Channel) channelView {
	var config notify.Config
	_ = json.Unmarshal([]byte(channel.Config), &config)
	view := channelView{Channel: channel, Config: config.Redacted()}
	if deliveries, err := store.Deliveries(channel.ID, 1); err == nil && len(deliveries) > 0 {
		view.Last = &deliveries[0]
	}
	return view
}

type notificationsResponse struct {
	Channels     []channelView    `json:"channels"`
	Deliveries   []store.Delivery `json:"deliveries"`
	DashboardURL string           `json:"dashboard_url"`
	Events       []string         `json:"events"`
}

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request) {
	channels, err := store.Channels()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	deliveries, err := store.Deliveries("", 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	base, _ := store.Meta(metaDashboardURL)
	response := notificationsResponse{Channels: make([]channelView, 0, len(channels)), Deliveries: deliveries, DashboardURL: base, Events: notify.Events}
	for _, channel := range channels {
		response.Channels = append(response.Channels, viewChannel(channel))
	}
	writeJSON(w, http.StatusOK, response)
}

type channelRequest struct {
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	Config     notify.Config `json:"config"`
	Enabled    *bool         `json:"enabled"`
	Events     []string      `json:"events"`
	Tags       []string      `json:"tags"`
	Digest     string        `json:"digest"`
	DigestDays []int         `json:"digest_days"`
	DigestTime string        `json:"digest_time"`
	Timezone   string        `json:"timezone"`
}

// apply checks request and writes it into channel, keeping saved secrets
// the request leaves empty.
func (request channelRequest) apply(channel *store.Channel, now time.Time) error {
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 80 {
		return errors.New("give the channel a name of up to 80 characters")
	}
	if channel.ID == "" {
		channel.Kind = request.Kind
	} else if request.Kind != "" && request.Kind != channel.Kind {
		return errors.New("a channel's type can't change; add a new channel instead")
	}
	var saved notify.Config
	_ = json.Unmarshal([]byte(channel.Config), &saved)
	config := saved.Merge(request.Config)
	config.Host, config.From = strings.TrimSpace(config.Host), strings.TrimSpace(config.From)
	if err := config.Validate(channel.Kind); err != nil {
		return err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	events := make([]string, 0, len(request.Events))
	for _, event := range request.Events {
		if !slices.Contains(notify.Events, event) {
			return fmt.Errorf("unknown event %q", event)
		}
		if !slices.Contains(events, event) {
			events = append(events, event)
		}
	}
	tags, err := store.NormalizeTags(request.Tags)
	if err != nil {
		return err
	}
	switch request.Digest {
	case "":
		request.DigestDays = nil
	case "daily", "weekly":
		if request.DigestTime == "" {
			request.DigestTime = "08:00"
		}
		if request.Timezone == "" {
			request.Timezone = "UTC"
		}
		if request.Digest == "daily" {
			request.DigestDays = nil
		}
	default:
		return errors.New("a digest is daily, weekly or none")
	}
	if request.Digest != "" && !slices.Contains(events, notify.EventDigest) {
		events = append(events, notify.EventDigest)
	}
	if request.Digest == "" && slices.Contains(events, notify.EventDigest) {
		return errors.New("choose when the digest goes out: daily or weekly")
	}
	channel.Name, channel.Config, channel.Events, channel.Tags = request.Name, string(encoded), events, tags
	channel.Digest, channel.DigestDays = request.Digest, request.DigestDays
	if channel.DigestDays == nil {
		channel.DigestDays = []int{}
	}
	if request.DigestTime != "" {
		channel.DigestTime = request.DigestTime
	}
	if request.Timezone != "" {
		channel.Timezone = request.Timezone
	}
	if request.Enabled != nil {
		channel.Enabled = *request.Enabled
	}
	channel.NextDigestAt = ""
	if channel.Digest != "" {
		next, err := digestWhen(*channel).Next(now)
		if err != nil {
			return fmt.Errorf("the digest's time: %w", err)
		}
		if channel.Enabled {
			channel.NextDigestAt = next.UTC().Format(time.RFC3339)
		}
	}
	return nil
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	var request channelRequest
	if !readJSON(w, r, &request) {
		return
	}
	channel := store.Channel{Enabled: true, CreatedBy: s.actor(r), DigestTime: "08:00", Timezone: "UTC"}
	if err := request.apply(&channel, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := store.SaveChannel(channel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "notification.add", saved.Name, saved.Kind+"; "+strings.Join(saved.Events, ", "))
	writeJSON(w, http.StatusCreated, viewChannel(saved))
}

func (s *Server) updateChannel(w http.ResponseWriter, r *http.Request) {
	channel, err := store.GetChannel(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	var request channelRequest
	if !readJSON(w, r, &request) {
		return
	}
	if err := request.apply(&channel, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := store.SaveChannel(channel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	detail := strings.Join(saved.Events, ", ")
	if !saved.Enabled {
		detail = "turned off"
	}
	s.audit(r, "notification.change", saved.Name, detail)
	writeJSON(w, http.StatusOK, viewChannel(saved))
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	channel, err := store.DeleteChannel(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "notification.remove", channel.Name, channel.Kind)
	writeJSON(w, http.StatusOK, viewChannel(channel))
}

// testChannel sends a test message at once and says how it went.
func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	channel, err := store.GetChannel(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	message := notify.Message{Event: notify.EventTest, Level: notify.LevelInfo, Title: "Test from DeaconGuard",
		Lines: []string{"This channel works. " + s.actor(r) + " sent this test from Settings, Notifications."}, Link: link("/notifications"), At: time.Now().UTC()}
	encoded, err := encodeMessage(message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id, err := store.EnqueueDelivery(channel.ID, message.Event, message.Title, encoded)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Sent now, not by the background sender, so the dashboard shows the result.
	delivery, _ := store.GetDelivery(id)
	sendErr := deliver(r.Context(), delivery)
	_ = store.DeliveryAttempted(id, sendErr, time.Time{})
	s.audit(r, "notification.test", channel.Name, map[bool]string{true: "sent", false: "failed"}[sendErr == nil])
	result, _ := store.GetDelivery(id)
	writeJSON(w, http.StatusOK, result)
}

type notificationSettings struct {
	DashboardURL string `json:"dashboard_url"`
}

func (s *Server) updateNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var request notificationSettings
	if !readJSON(w, r, &request) {
		return
	}
	address := strings.TrimSuffix(strings.TrimSpace(request.DashboardURL), "/")
	if address != "" {
		parsed, err := url.Parse(address)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" {
			writeError(w, http.StatusBadRequest, errors.New("the dashboard's address looks like https://deaconguard.example.com"))
			return
		}
	}
	if err := store.SetMeta(metaDashboardURL, address); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "notification.settings", "dashboard address", address)
	writeJSON(w, http.StatusOK, notificationSettings{DashboardURL: address})
}
