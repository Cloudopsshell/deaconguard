package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/runstate"
)

// A running scan can pause in a needs_* status while it waits for the user to
// enter a sudo password, then resumes. A scan of an agent host is queued until
// its agent picks it up.
const (
	ScanQueued    = "queued"
	ScanRunning   = "running"
	ScanSucceeded = "succeeded"
	ScanFailed    = "failed"
	ScanNeedsSudo = "needs_sudo"
)

const unfinishedStatuses = "('queued', 'running', 'needs_sudo')"

// activeStatuses are the unfinished statuses of a scan that some process is
// working on, as opposed to one queued for an agent.
const activeStatuses = "('running', 'needs_sudo')"

// IsUnfinished reports whether a scan may still produce a result.
func IsUnfinished(status string) bool {
	return status == ScanQueued || status == ScanRunning || IsWaiting(status)
}

func IsWaiting(status string) bool {
	return status == ScanNeedsSudo
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

func (counts *SeverityCounts) add(severity string) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		counts.Critical++
	case "HIGH":
		counts.High++
	case "MEDIUM":
		counts.Medium++
	case "LOW":
		counts.Low++
	default:
		counts.Unknown++
	}
}

// FixSummary sums a scan's package findings by what clears them.
type FixSummary struct {
	// Counts holds the number of findings in each fix state: available,
	// reboot, old_kernel, ubuntu_pro, and none.
	Counts map[string]int `json:"counts"`
	// Actionable counts, by severity, the findings that installing updates
	// or restarting fixes.
	Actionable SeverityCounts `json:"actionable"`
}

// fixStates are the fix states, as advisory.Classify sets them.
var fixStates = []string{"available", "reboot", "old_kernel", "ubuntu_pro", "none"}

// actionableFix reports whether installing updates or restarting fixes a
// finding in this state.
func actionableFix(fix string) bool { return fix == "available" || fix == "reboot" }

// findingFix is a finding's fix state; reports from before 0.7.0 only say
// whether a fixed version exists.
func findingFix(fix, fixedVersion string) string {
	for _, state := range fixStates {
		if fix == state {
			return fix
		}
	}
	if fixedVersion == "" {
		return "none"
	}
	return "available"
}

func decodeFixSummary(value string) *FixSummary {
	if value == "" {
		return nil
	}
	var summary FixSummary
	if json.Unmarshal([]byte(value), &summary) != nil {
		return nil
	}
	return &summary
}

// Scan is one scan attempt. Only succeeded scans carry a report; any other
// status must never be read as a clean result.
type Scan struct {
	ID               string         `json:"id"`
	HostID           string         `json:"host_id"`
	Address          string         `json:"address"`
	Status           string         `json:"status"`
	Error            string         `json:"error,omitempty"`
	StartedAt        string         `json:"started_at"`
	FinishedAt       *string        `json:"finished_at"`
	OS               string         `json:"os"`
	FindingCount     int            `json:"finding_count"`
	UnsupportedCount int            `json:"unsupported_count"`
	Severity         SeverityCounts `json:"severity"`
	// Fixes sums package findings by what clears them; nil when the scan
	// did not check packages.
	Fixes     *FixSummary `json:"fixes,omitempty"`
	FeedStale bool        `json:"feed_stale"`
	// Checks lists the checks this scan ran. Package counts above are only
	// meaningful when it includes CheckPackages.
	Checks []string `json:"checks"`
	// HasLog reports whether the scan's activity log was saved.
	HasLog bool `json:"has_log"`
}

// CheckPackages is the package vulnerability check every earlier scan ran.
const CheckPackages = "packages"

const scanColumns = `id, host_id, address, status, error, started_at, finished_at, os,
	finding_count, unsupported_count, critical, high, medium, low, unknown, feed_stale, checks, events_json IS NOT NULL, fix_summary`

func encodeChecks(checks []string) string { return "," + strings.Join(checks, ",") + "," }

func decodeChecks(value string) []string {
	checks := make([]string, 0)
	for _, check := range strings.Split(value, ",") {
		if check != "" {
			checks = append(checks, check)
		}
	}
	return checks
}

func scanScan(row rowScanner) (Scan, error) {
	var scan Scan
	var finishedAt sql.NullString
	var feedStale int
	var checks, fixSummary string
	err := row.Scan(&scan.ID, &scan.HostID, &scan.Address, &scan.Status, &scan.Error, &scan.StartedAt, &finishedAt, &scan.OS, &scan.FindingCount, &scan.UnsupportedCount,
		&scan.Severity.Critical, &scan.Severity.High, &scan.Severity.Medium, &scan.Severity.Low, &scan.Severity.Unknown,
		&feedStale, &checks, &scan.HasLog, &fixSummary)
	if err != nil {
		return Scan{}, err
	}
	scan.Fixes = decodeFixSummary(fixSummary)
	if finishedAt.Valid {
		value := finishedAt.String
		scan.FinishedAt = &value
	}
	scan.FeedStale = feedStale != 0
	scan.Checks = decodeChecks(checks)
	return scan, nil
}

// CreateScan records a scan of the given checks that has started for host.
func CreateScan(host Host, checks []string) (Scan, error) {
	return createScan(host, checks, ScanRunning)
}

// QueueScan records a scan of an agent host for its agent to pick up.
func QueueScan(host Host, checks []string) (Scan, error) {
	if host.Transport != TransportAgent {
		return Scan{}, fmt.Errorf("only agent hosts have queued scans")
	}
	return createScan(host, checks, ScanQueued)
}

func createScan(host Host, checks []string, status string) (Scan, error) {
	if len(checks) == 0 {
		return Scan{}, fmt.Errorf("choose at least one check")
	}
	db, err := database()
	if err != nil {
		return Scan{}, err
	}
	id, err := newID()
	if err != nil {
		return Scan{}, err
	}
	if _, err := db.Exec("INSERT INTO scans (id, host_id, address, status, started_at, checks) VALUES (?, ?, ?, ?, ?, ?)",
		id, host.ID, host.Address, status, nowText(), encodeChecks(checks)); err != nil {
		return Scan{}, err
	}
	return GetScan(id)
}

// CompleteScan attaches a finished report to a running scan.
func CompleteScan(id string, report map[string]any) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := applyReport(tx, id, report, nowText()); err != nil {
		return err
	}
	return tx.Commit()
}

// WaitForInput pauses a running scan until the user responds. message
// explains why an earlier answer was rejected, if it was.
func WaitForInput(id, status, message string) error {
	if !IsWaiting(status) {
		return fmt.Errorf("invalid waiting scan status %q", status)
	}
	return updateScan(`UPDATE scans SET status = ?, error = ? WHERE id = ? AND status = ?`,
		status, message, id, ScanRunning)
}

// ResumeScan returns a waiting scan to running once the user has responded.
func ResumeScan(id string) error {
	return updateScan(`UPDATE scans SET status = ?, error = '' WHERE id = ? AND status IN `+
		activeStatuses, ScanRunning, id)
}

// FailScan records why an unfinished scan stopped without a report.
func FailScan(id, message string) error {
	return updateScan(`UPDATE scans SET status = ?, error = ?, finished_at = ?
		WHERE id = ? AND status IN `+unfinishedStatuses, ScanFailed, message, nowText(), id)
}

func updateScan(query string, arguments ...any) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec(query, arguments...)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return err
	} else if changed != 1 {
		return fmt.Errorf("scan is not in progress")
	}
	return nil
}

// SaveScanEvents stores a finished scan's activity log as JSON.
func SaveScanEvents(id string, events []byte) error {
	return updateScan("UPDATE scans SET events_json = ? WHERE id = ?", string(events), id)
}

// ScanEvents returns a scan's saved activity log, or nil if it has none.
func ScanEvents(id string) ([]byte, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	var events sql.NullString
	err = db.QueryRow("SELECT events_json FROM scans WHERE id = ?", id).Scan(&events)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !events.Valid) {
		return nil, nil
	}
	return []byte(events.String), err
}

// KeepScansPerHost is how many scans of each host are kept; older ones are pruned.
const KeepScansPerHost = 10

var ErrScanInProgress = errors.New("a scan that is still running cannot be deleted")

// DeleteScan removes one finished scan with its findings and log. A scan still
// queued for its agent is cancelled this way too.
func DeleteScan(id string) error {
	scan, err := GetScan(id)
	if err != nil {
		return err
	}
	if scan.Status == ScanRunning || IsWaiting(scan.Status) {
		return ErrScanInProgress
	}
	db, err := database()
	if err != nil {
		return err
	}
	if scan.Status == ScanQueued {
		// The agent may have claimed it in the meantime.
		result, err := db.Exec("DELETE FROM scans WHERE id = ? AND status = ?", id, ScanQueued)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed == 0 {
			return ErrScanInProgress
		}
		return nil
	}
	_, err = db.Exec("DELETE FROM scans WHERE id = ?", id)
	return err
}

// PruneScans deletes a host's finished scans beyond the newest keep. A scan
// that is still the newest successful result of any check is kept, so no
// result tab loses its data.
func PruneScans(hostID string, keep int) (int, error) {
	db, err := database()
	if err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	protected := make(map[string]bool)
	rows, err := tx.Query(`SELECT c.check_id, s.id FROM scan_checks c JOIN scans s ON s.id = c.scan_id
		WHERE s.host_id = ? AND s.status = ? ORDER BY s.started_at DESC, s.rowid DESC`, hostID, ScanSucceeded)
	if err != nil {
		return 0, err
	}
	seenCheck := make(map[string]bool)
	for rows.Next() {
		var check, id string
		if err := rows.Scan(&check, &id); err != nil {
			rows.Close()
			return 0, err
		}
		if !seenCheck[check] {
			seenCheck[check] = true
			protected[id] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows, err = tx.Query(`SELECT id, status FROM scans WHERE host_id = ? ORDER BY started_at DESC, rowid DESC`, hostID)
	if err != nil {
		return 0, err
	}
	var stale []string
	for position := 0; rows.Next(); position++ {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			rows.Close()
			return 0, err
		}
		if position >= keep && !protected[id] && !IsUnfinished(status) {
			stale = append(stale, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range stale {
		if _, err := tx.Exec("DELETE FROM scans WHERE id = ?", id); err != nil {
			return 0, err
		}
	}
	return len(stale), tx.Commit()
}

// PruneAllScans applies PruneScans to every registered host.
func PruneAllScans(keep int) error {
	hosts, err := ListHosts()
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if _, err := PruneScans(host.ID, keep); err != nil {
			return err
		}
	}
	return nil
}

// InterruptRunningScans fails scans left unfinished by a previous process,
// saying why that process stopped when it is known. Queued scans stay queued
// for their agents.
func InterruptRunningScans(why *runstate.Stop) error {
	db, err := database()
	if err != nil {
		return err
	}
	message := "The DeaconGuard server stopped while this scan was running."
	if why != nil {
		message += " " + why.Message
	}
	message += " Run the scan again."
	_, err = db.Exec(`UPDATE scans SET status = ?, error = ?, finished_at = COALESCE(finished_at, ?)
		WHERE status IN `+activeStatuses, ScanFailed, message, nowText())
	return err
}

// ClaimQueuedScan marks the oldest queued scan of hostID as running and
// returns it; found is false when nothing is queued.
func ClaimQueuedScan(hostID string) (scan Scan, found bool, err error) {
	db, err := database()
	if err != nil {
		return Scan{}, false, err
	}
	for {
		var id string
		err := db.QueryRow("SELECT id FROM scans WHERE host_id = ? AND status = ? ORDER BY started_at, rowid LIMIT 1",
			hostID, ScanQueued).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return Scan{}, false, nil
		}
		if err != nil {
			return Scan{}, false, err
		}
		result, err := db.Exec("UPDATE scans SET status = ? WHERE id = ? AND status = ?", ScanRunning, id, ScanQueued)
		if err != nil {
			return Scan{}, false, err
		}
		if changed, _ := result.RowsAffected(); changed == 1 {
			scan, err := GetScan(id)
			return scan, err == nil, err
		}
		// Another request claimed or cancelled it first; look again.
	}
}

// ExpireQueuedScans fails scans that stayed queued since before cutoff,
// because their agent never picked them up, and returns their IDs.
func ExpireQueuedScans(cutoff time.Time, message string) ([]string, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT id FROM scans WHERE status = ? AND started_at < ?", ScanQueued, cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	expired := make([]string, 0, len(ids))
	for _, id := range ids {
		if err := updateScan(`UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ? AND status = ?`,
			ScanFailed, message, nowText(), id, ScanQueued); err == nil {
			expired = append(expired, id)
		}
	}
	return expired, nil
}

// UnfinishedScan returns hostID's queued or running scan, if it has one.
func UnfinishedScan(hostID string) (Scan, bool, error) {
	db, err := database()
	if err != nil {
		return Scan{}, false, err
	}
	scan, err := scanScan(db.QueryRow("SELECT "+scanColumns+" FROM scans WHERE host_id = ? AND status IN "+
		unfinishedStatuses+" ORDER BY started_at DESC, rowid DESC LIMIT 1", hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, false, nil
	}
	return scan, err == nil, err
}

func GetScan(id string) (Scan, error) {
	db, err := database()
	if err != nil {
		return Scan{}, err
	}
	scan, err := scanScan(db.QueryRow("SELECT "+scanColumns+" FROM scans WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, fmt.Errorf("scan not found")
	}
	return scan, err
}

// ListScans returns scans for one host, newest first.
func ListScans(hostID string, limit int) ([]Scan, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.Query("SELECT "+scanColumns+" FROM scans WHERE host_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?",
		hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := make([]Scan, 0)
	for rows.Next() {
		scan, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

type HostSummary struct {
	Host
	LastScan *Scan `json:"last_scan"`
	// LastReport is the newest successful scan that checked packages.
	LastReport *Scan `json:"last_report"`
	// Checks holds the newest successful result of every check run on the host.
	Checks map[string]CheckSummary `json:"checks"`
	// Agent describes the agent of an agent host.
	Agent *Agent `json:"agent,omitempty"`
}

// CheckSummary is one check's result within a scan.
type CheckSummary struct {
	Check        string         `json:"check"`
	ScanID       string         `json:"scan_id"`
	ScannedAt    string         `json:"scanned_at"`
	Status       string         `json:"status"`
	Privileged   bool           `json:"privileged"`
	Summary      string         `json:"summary"`
	FindingCount int            `json:"finding_count"`
	Severity     SeverityCounts `json:"severity"`
	// Fixes is set for the package check.
	Fixes *FixSummary `json:"fixes,omitempty"`
}

// HostSummaries lists registered hosts with their newest scan attempt and
// newest successful report.
func HostSummaries() ([]HostSummary, error) {
	hosts, err := ListHosts()
	if err != nil {
		return nil, err
	}
	db, err := database()
	if err != nil {
		return nil, err
	}
	agents, err := Agents()
	if err != nil {
		return nil, err
	}
	summaries := make([]HostSummary, 0, len(hosts))
	for _, host := range hosts {
		summary := HostSummary{Host: host}
		if agent, ok := agents[host.ID]; ok {
			summary.Agent = &agent
		}
		last, err := scanScan(db.QueryRow("SELECT "+scanColumns+
			" FROM scans WHERE host_id = ? ORDER BY started_at DESC, rowid DESC LIMIT 1", host.ID))
		if err == nil {
			summary.LastScan = &last
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		report, err := scanScan(db.QueryRow("SELECT "+scanColumns+
			" FROM scans WHERE host_id = ? AND status = ? AND checks LIKE ? ORDER BY started_at DESC, rowid DESC LIMIT 1",
			host.ID, ScanSucceeded, "%,"+CheckPackages+",%"))
		if err == nil {
			summary.LastReport = &report
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if summary.Checks, err = latestChecks(db, host.ID); err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func latestChecks(db *sql.DB, hostID string) (map[string]CheckSummary, error) {
	rows, err := db.Query(`SELECT c.check_id, c.scan_id, s.started_at, c.status, c.privileged, c.summary, c.finding_count,
		c.critical, c.high, c.medium, c.low, c.unknown, c.fix_summary
		FROM scan_checks c JOIN scans s ON s.id = c.scan_id
		WHERE s.host_id = ? AND s.status = ? ORDER BY s.started_at DESC, s.rowid DESC`, hostID, ScanSucceeded)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checks := make(map[string]CheckSummary)
	for rows.Next() {
		var item CheckSummary
		var fixSummary string
		if err := rows.Scan(&item.Check, &item.ScanID, &item.ScannedAt, &item.Status, &item.Privileged, &item.Summary,
			&item.FindingCount, &item.Severity.Critical, &item.Severity.High, &item.Severity.Medium, &item.Severity.Low,
			&item.Severity.Unknown, &fixSummary); err != nil {
			return nil, err
		}
		item.Fixes = decodeFixSummary(fixSummary)
		if _, seen := checks[item.Check]; !seen {
			checks[item.Check] = item
		}
	}
	return checks, rows.Err()
}

type Vulnerability struct {
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	// FixableHosts counts the hosts where installing updates or restarting
	// fixes it.
	FixableHosts int      `json:"fixable_host_count"`
	Title        string   `json:"title"`
	URL          string   `json:"url"`
	HostCount    int      `json:"host_count"`
	Packages     []string `json:"packages"`
}

type AffectedPackage struct {
	HostID           string `json:"host_id"`
	Address          string `json:"address"`
	ScanID           string `json:"scan_id"`
	ScannedAt        string `json:"scanned_at"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Fix              string `json:"fix"`
	Severity         string `json:"severity"`
	URL              string `json:"url"`
	Title            string `json:"title"`
}

// latestFindings selects findings from the newest successful scan of each
// registered host.
const latestFindings = `
SELECT s.host_id, h.address, s.id, s.started_at, f.cve, f.package, f.installed_version, f.fixed_version,
	f.fix, f.severity, f.url, f.title
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN hosts h ON h.id = s.host_id
WHERE s.id = (
	SELECT latest.id FROM scans latest
	WHERE latest.host_id = s.host_id AND latest.status = 'succeeded' AND latest.checks LIKE '%,packages,%'
	ORDER BY latest.started_at DESC, latest.rowid DESC LIMIT 1
)`

func queryLatestFindings(filter string, arguments ...any) ([]AffectedPackage, []string, error) {
	db, err := database()
	if err != nil {
		return nil, nil, err
	}
	rows, err := db.Query(latestFindings+filter+" ORDER BY h.address, f.package", arguments...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	affected := make([]AffectedPackage, 0)
	cves := make([]string, 0)
	for rows.Next() {
		var item AffectedPackage
		var cve string
		if err := rows.Scan(&item.HostID, &item.Address, &item.ScanID, &item.ScannedAt, &cve, &item.Package,
			&item.InstalledVersion, &item.FixedVersion, &item.Fix, &item.Severity, &item.URL, &item.Title); err != nil {
			return nil, nil, err
		}
		item.Fix = findingFix(item.Fix, item.FixedVersion)
		affected = append(affected, item)
		cves = append(cves, cve)
	}
	return affected, cves, rows.Err()
}

// Vulnerabilities groups the latest findings across all hosts by CVE.
func Vulnerabilities() ([]Vulnerability, error) {
	affected, cves, err := queryLatestFindings("")
	if err != nil {
		return nil, err
	}
	byCVE := make(map[string]*Vulnerability)
	hosts := make(map[string]map[string]bool)
	fixable := make(map[string]map[string]bool)
	packages := make(map[string]map[string]bool)
	for index, item := range affected {
		cve := cves[index]
		vulnerability, ok := byCVE[cve]
		if !ok {
			vulnerability = &Vulnerability{CVE: cve, Severity: item.Severity, Title: item.Title, URL: item.URL}
			byCVE[cve] = vulnerability
			hosts[cve] = make(map[string]bool)
			fixable[cve] = make(map[string]bool)
			packages[cve] = make(map[string]bool)
		}
		if severityRank(item.Severity) > severityRank(vulnerability.Severity) {
			vulnerability.Severity = item.Severity
		}
		hosts[cve][item.HostID] = true
		if actionableFix(item.Fix) {
			fixable[cve][item.HostID] = true
		}
		packages[cve][item.Package] = true
	}
	result := make([]Vulnerability, 0, len(byCVE))
	for cve, vulnerability := range byCVE {
		vulnerability.HostCount = len(hosts[cve])
		vulnerability.FixableHosts = len(fixable[cve])
		for name := range packages[cve] {
			vulnerability.Packages = append(vulnerability.Packages, name)
		}
		sort.Strings(vulnerability.Packages)
		result = append(result, *vulnerability)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := severityRank(result[i].Severity), severityRank(result[j].Severity)
		if left != right {
			return left > right
		}
		if result[i].HostCount != result[j].HostCount {
			return result[i].HostCount > result[j].HostCount
		}
		return result[i].CVE > result[j].CVE
	})
	return result, nil
}

// VulnerabilityHosts lists the installed packages affected by one CVE in each
// host's latest successful scan.
func VulnerabilityHosts(cve string) ([]AffectedPackage, error) {
	affected, _, err := queryLatestFindings(" AND f.cve = ?", cve)
	return affected, err
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

type findingRecord struct {
	ID               string `json:"id"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Fix              string `json:"fix"`
	CVSSSeverity     string `json:"cvss_severity"`
	Severity         string `json:"severity"`
	URL              string `json:"url"`
	Title            string `json:"title"`
}

// insertReport stores a report produced outside the server, such as a CLI scan
// or a report file from an earlier release.
func insertReport(tx *sql.Tx, id string, report map[string]any) error {
	hostID, _ := report["host_id"].(string)
	address, _ := report["address"].(string)
	scannedAt := nowText()
	if value, ok := report["scanned_at"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			scannedAt = parsed.UTC().Format(time.RFC3339)
		}
	}
	checks := reportChecks(report)
	if _, err := tx.Exec("INSERT INTO scans (id, host_id, address, status, started_at, checks) VALUES (?, ?, ?, ?, ?, ?)",
		id, hostID, address, ScanRunning, scannedAt, encodeChecks(checks)); err != nil {
		return err
	}
	return applyReport(tx, id, report, scannedAt)
}

// reportChecks lists the checks a report covers. Reports from before checks
// existed only covered packages.
func reportChecks(report map[string]any) []string {
	values, ok := report["checks_run"].([]any)
	if !ok {
		if list, ok := report["checks_run"].([]string); ok {
			return list
		}
		return []string{CheckPackages}
	}
	checks := make([]string, 0, len(values))
	for _, value := range values {
		if check, ok := value.(string); ok {
			checks = append(checks, check)
		}
	}
	return checks
}

// checkResultRecord mirrors checks.Result as stored in report JSON.
type checkResultRecord struct {
	Status     string   `json:"status"`
	Privileged bool     `json:"privileged"`
	Summary    string   `json:"summary"`
	Notes      []string `json:"notes"`
	Error      string   `json:"error"`
	Findings   []struct {
		Rule     string `json:"rule"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		Evidence string `json:"evidence"`
	} `json:"findings"`
}

func insertCheckResults(tx *sql.Tx, id string, report map[string]any, packageCounts SeverityCounts, packageFindings, unsupported int, fixSummary string) error {
	for _, check := range reportChecks(report) {
		if check != CheckPackages {
			continue
		}
		status := "completed"
		if unsupported > 0 {
			status = "partial"
		}
		if _, err := tx.Exec(`INSERT INTO scan_checks (scan_id, check_id, status, finding_count, critical, high, medium, low, unknown, fix_summary)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, CheckPackages, status, packageFindings,
			packageCounts.Critical, packageCounts.High, packageCounts.Medium, packageCounts.Low, packageCounts.Unknown, fixSummary); err != nil {
			return err
		}
	}
	raw, ok := report["check_results"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var results map[string]checkResultRecord
	if err := json.Unmarshal(encoded, &results); err != nil {
		return fmt.Errorf("read check results: %w", err)
	}
	for check, result := range results {
		var counts SeverityCounts
		for _, finding := range result.Findings {
			counts.add(finding.Severity)
			if _, err := tx.Exec(`INSERT INTO check_findings (scan_id, check_id, rule, severity, title, detail, evidence)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, id, check, finding.Rule, strings.ToUpper(finding.Severity),
				finding.Title, finding.Detail, finding.Evidence); err != nil {
				return err
			}
		}
		notes, err := json.Marshal(result.Notes)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO scan_checks (scan_id, check_id, status, privileged, summary, notes, error,
			finding_count, critical, high, medium, low, unknown) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, check, result.Status, result.Privileged, result.Summary, string(notes), result.Error, len(result.Findings),
			counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown); err != nil {
			return err
		}
	}
	return nil
}

func applyReport(tx *sql.Tx, id string, report map[string]any, finishedAt string) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	findings := make([]findingRecord, 0)
	if raw, ok := report["findings"]; ok && raw != nil {
		encodedFindings, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(encodedFindings, &findings); err != nil {
			return fmt.Errorf("read report findings: %w", err)
		}
	}
	var counts SeverityCounts
	fixes := FixSummary{Counts: make(map[string]int, len(fixStates))}
	for _, state := range fixStates {
		fixes.Counts[state] = 0
	}
	for index, finding := range findings {
		counts.add(finding.Severity)
		findings[index].Fix = findingFix(finding.Fix, finding.FixedVersion)
		fixes.Counts[findings[index].Fix]++
		if actionableFix(findings[index].Fix) {
			fixes.Actionable.add(finding.Severity)
		}
	}
	fixSummary := ""
	if slices.Contains(reportChecks(report), CheckPackages) {
		encodedFixes, err := json.Marshal(fixes)
		if err != nil {
			return err
		}
		fixSummary = string(encodedFixes)
	}
	operatingSystem, _ := report["os"].(string)
	unsupported := 0
	if values, ok := report["unsupported_cves"].([]any); ok {
		unsupported = len(values)
	} else if count, ok := report["unsupported_count"].(float64); ok {
		unsupported = int(count)
	} else if count, ok := report["unsupported_count"].(int); ok {
		unsupported = count
	}
	feedStale := 0
	if metadata, ok := report["advisory_database"].(map[string]any); ok {
		if stale, _ := metadata["feed_stale"].(bool); stale {
			feedStale = 1
		}
	}
	result, err := tx.Exec(`UPDATE scans SET status = ?, error = '', finished_at = ?, os = ?,
		finding_count = ?, unsupported_count = ?, critical = ?, high = ?, medium = ?, low = ?, unknown = ?,
		feed_stale = ?, report_json = ?, fix_summary = ? WHERE id = ? AND status = ?`,
		ScanSucceeded, finishedAt, operatingSystem, len(findings), unsupported,
		counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown,
		feedStale, string(encoded), fixSummary, id, ScanRunning)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return err
	} else if changed != 1 {
		return fmt.Errorf("scan %s is not running", id)
	}
	if err := insertCheckResults(tx, id, report, counts, len(findings), unsupported, fixSummary); err != nil {
		return err
	}
	for _, finding := range findings {
		if _, err := tx.Exec(`INSERT INTO findings (scan_id, cve, package, installed_version, fixed_version, fix, severity, cvss_severity, url, title)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, finding.ID, finding.Package, finding.InstalledVersion,
			finding.FixedVersion, finding.Fix, strings.ToUpper(finding.Severity), strings.ToUpper(finding.CVSSSeverity), finding.URL, finding.Title); err != nil {
			return err
		}
	}
	return nil
}
