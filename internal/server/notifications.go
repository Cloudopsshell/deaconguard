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
// vulnerabilities known to be exploited or critical ones with a fix;
// malware; changed system files; and an audit's grade.
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
	if slices.Contains(record.Checks, checks.Kubernetes) {
		s.newClusterFindings(host, record, scanLink)
	}
	counts, err := store.ScanCheckCounts(scanID)
	if err != nil {
		serverLog(host.ID, store.LogError, "Could not read the results of the scan of %s for notifications: %v", host.Address, err)
		return
	}
	malware := counts[checks.Malware].Findings + counts[checks.Antivirus].Findings + counts[checks.YARA].Findings
	if malware > 0 {
		s.emit(notify.Message{Event: notify.EventMalware, Level: notify.LevelCritical,
			Title: fmt.Sprintf("%s: malware or signs of compromise found (%s)", host.Address, plural(malware, "finding", "findings")),
			Lines: []string{"Look at the scan now; treat the host as compromised until you know otherwise."},
			Link:  scanLink, HostID: host.ID, Host: host.Address, ScanID: scanID, Data: map[string]any{"findings": malware}})
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

// clusterFindings are a scan's critical and high Kubernetes findings, by rule
// and title, which name the object.
func clusterFindings(scanID string) (map[string]checks.Finding, bool) {
	report, err := store.GetFullReport(scanID)
	if err != nil {
		return nil, false
	}
	encoded, _ := json.Marshal(report["check_results"])
	var results map[string]checks.Result
	if json.Unmarshal(encoded, &results) != nil {
		return nil, false
	}
	result, ok := results[checks.Kubernetes]
	if !ok || result.Status == checks.StatusFailed {
		return nil, false
	}
	found := map[string]checks.Finding{}
	for _, f := range result.Findings {
		if severity := strings.ToUpper(f.Severity); severity == "CRITICAL" || severity == "HIGH" {
			found[f.Rule+"\x00"+f.Title] = f
		}
	}
	return found, true
}

// newClusterFindings notifies about a cluster's critical and high findings
// its previous Kubernetes scan didn't have, such as a privileged workload
// deployed since.
func (s *Server) newClusterFindings(host store.Host, record store.Scan, scanLink string) {
	current, ok := clusterFindings(record.ID)
	if !ok {
		return
	}
	previous := map[string]checks.Finding{}
	if scans, err := store.ListScans(host.ID, 50); err == nil {
		for _, earlier := range scans {
			if earlier.ID == record.ID || earlier.Status != store.ScanSucceeded || !slices.Contains(earlier.Checks, checks.Kubernetes) ||
				earlier.StartedAt > record.StartedAt {
				continue
			}
			if found, ok := clusterFindings(earlier.ID); ok {
				previous = found
				break
			}
		}
	}
	var added []checks.Finding
	critical := false
	for key, f := range current {
		if _, seen := previous[key]; !seen {
			added = append(added, f)
			critical = critical || strings.EqualFold(f.Severity, "CRITICAL")
		}
	}
	if len(added) == 0 {
		return
	}
	sort.Slice(added, func(i, j int) bool {
		if added[i].Severity != added[j].Severity {
			return strings.EqualFold(added[i].Severity, "CRITICAL")
		}
		return added[i].Title < added[j].Title
	})
	level := notify.LevelWarning
	if critical {
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
	s.emit(notify.Message{Event: notify.EventCluster, Level: level,
		Title: fmt.Sprintf("%s: %s", host.Address, plural(len(added), "new critical or high finding", "new critical or high findings")),
		Lines: lines, Link: scanLink, HostID: host.ID, Host: host.Address, ScanID: record.ID, Data: map[string]any{"rules": rules}})
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
	tagged := map[string]bool{}
	for _, host := range result.HostSummaries {
		if !inScope(host.Tags) {
			continue
		}
		hosts++
		tagged[host.ID] = true
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
			"known_exploited": known, "known_exploited_fixable": knownFixable, "likely_exploited": likely}}
	// Only email carries files.
	if channel.Kind == notify.Email {
		message.Lines = append(message.Lines, fmt.Sprintf("Attached: every open vulnerability (%d rows), as CSV.", rows))
		message.Attachment = &notify.Attachment{Name: "deaconguard-vulnerabilities-" + now.Format("2006-01-02") + ".csv", ContentType: "text/csv", Data: table.Bytes()}
	}
	return message, nil
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
