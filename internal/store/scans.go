package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// A running scan can pause in a needs_* status while it waits for the user to
// approve a host key or enter a passphrase or password, then resumes.
const (
	ScanRunning         = "running"
	ScanSucceeded       = "succeeded"
	ScanFailed          = "failed"
	ScanNeedsTrust      = "needs_trust"
	ScanNeedsPassphrase = "needs_passphrase"
	ScanNeedsPassword   = "needs_password"
	ScanNeedsSudo       = "needs_sudo"
)

const unfinishedStatuses = "('running', 'needs_trust', 'needs_passphrase', 'needs_password', 'needs_sudo')"

func IsWaiting(status string) bool {
	return status == ScanNeedsTrust || status == ScanNeedsPassphrase || status == ScanNeedsPassword || status == ScanNeedsSudo
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

// Scan is one scan attempt. Only succeeded scans carry a report; any other
// status must never be read as a clean result.
type Scan struct {
	ID                 string         `json:"id"`
	HostID             string         `json:"host_id"`
	Address            string         `json:"address"`
	Status             string         `json:"status"`
	Error              string         `json:"error,omitempty"`
	HostKeyFingerprint string         `json:"host_key_fingerprint,omitempty"`
	StartedAt          string         `json:"started_at"`
	FinishedAt         *string        `json:"finished_at"`
	OS                 string         `json:"os"`
	FindingCount       int            `json:"finding_count"`
	UnsupportedCount   int            `json:"unsupported_count"`
	Severity           SeverityCounts `json:"severity"`
	FeedStale          bool           `json:"feed_stale"`
	// Checks lists the checks this scan ran. Package counts above are only
	// meaningful when it includes CheckPackages.
	Checks []string `json:"checks"`
	// HasLog reports whether the scan's activity log was saved.
	HasLog bool `json:"has_log"`
}

// CheckPackages is the package vulnerability check every earlier scan ran.
const CheckPackages = "packages"

const scanColumns = `id, host_id, address, status, error, host_key_fingerprint, started_at, finished_at, os,
	finding_count, unsupported_count, critical, high, medium, low, unknown, feed_stale, checks, events_json IS NOT NULL`

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
	var checks string
	err := row.Scan(&scan.ID, &scan.HostID, &scan.Address, &scan.Status, &scan.Error, &scan.HostKeyFingerprint,
		&scan.StartedAt, &finishedAt, &scan.OS, &scan.FindingCount, &scan.UnsupportedCount,
		&scan.Severity.Critical, &scan.Severity.High, &scan.Severity.Medium, &scan.Severity.Low, &scan.Severity.Unknown,
		&feedStale, &checks, &scan.HasLog)
	if err != nil {
		return Scan{}, err
	}
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
		id, host.ID, host.Address, ScanRunning, nowText(), encodeChecks(checks)); err != nil {
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
func WaitForInput(id, status, message, fingerprint string) error {
	if !IsWaiting(status) {
		return fmt.Errorf("invalid waiting scan status %q", status)
	}
	return updateScan(`UPDATE scans SET status = ?, error = ?, host_key_fingerprint = ? WHERE id = ? AND status = ?`,
		status, message, fingerprint, id, ScanRunning)
}

// ResumeScan returns a waiting scan to running once the user has responded.
func ResumeScan(id string) error {
	return updateScan(`UPDATE scans SET status = ?, error = '', host_key_fingerprint = '' WHERE id = ? AND status IN `+
		unfinishedStatuses, ScanRunning, id)
}

// FailScan records why an unfinished scan stopped without a report.
func FailScan(id, message string) error {
	return updateScan(`UPDATE scans SET status = ?, error = ?, host_key_fingerprint = '', finished_at = ?
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

// DeleteScan removes one finished scan with its findings and log.
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
		if position >= keep && !protected[id] && status != ScanRunning && !IsWaiting(status) {
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

// InterruptRunningScans fails scans left unfinished by a previous process.
func InterruptRunningScans() error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE scans SET status = ?, error = ?, host_key_fingerprint = '', finished_at = COALESCE(finished_at, ?)
		WHERE status IN `+unfinishedStatuses, ScanFailed, "scan was interrupted before it finished", nowText())
	return err
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
	summaries := make([]HostSummary, 0, len(hosts))
	for _, host := range hosts {
		summary := HostSummary{Host: host}
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
		c.critical, c.high, c.medium, c.low, c.unknown
		FROM scan_checks c JOIN scans s ON s.id = c.scan_id
		WHERE s.host_id = ? AND s.status = ? ORDER BY s.started_at DESC, s.rowid DESC`, hostID, ScanSucceeded)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checks := make(map[string]CheckSummary)
	for rows.Next() {
		var item CheckSummary
		if err := rows.Scan(&item.Check, &item.ScanID, &item.ScannedAt, &item.Status, &item.Privileged, &item.Summary,
			&item.FindingCount, &item.Severity.Critical, &item.Severity.High, &item.Severity.Medium, &item.Severity.Low,
			&item.Severity.Unknown); err != nil {
			return nil, err
		}
		if _, seen := checks[item.Check]; !seen {
			checks[item.Check] = item
		}
	}
	return checks, rows.Err()
}

type Vulnerability struct {
	CVE       string   `json:"cve"`
	Severity  string   `json:"severity"`
	Title     string   `json:"title"`
	URL       string   `json:"url"`
	HostCount int      `json:"host_count"`
	Packages  []string `json:"packages"`
}

type AffectedPackage struct {
	HostID           string `json:"host_id"`
	Address          string `json:"address"`
	ScanID           string `json:"scan_id"`
	ScannedAt        string `json:"scanned_at"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Severity         string `json:"severity"`
	URL              string `json:"url"`
	Title            string `json:"title"`
}

// latestFindings selects findings from the newest successful scan of each
// registered host.
const latestFindings = `
SELECT s.host_id, h.address, s.id, s.started_at, f.cve, f.package, f.installed_version, f.fixed_version,
	f.severity, f.url, f.title
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
			&item.InstalledVersion, &item.FixedVersion, &item.Severity, &item.URL, &item.Title); err != nil {
			return nil, nil, err
		}
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
	packages := make(map[string]map[string]bool)
	for index, item := range affected {
		cve := cves[index]
		vulnerability, ok := byCVE[cve]
		if !ok {
			vulnerability = &Vulnerability{CVE: cve, Severity: item.Severity, Title: item.Title, URL: item.URL}
			byCVE[cve] = vulnerability
			hosts[cve] = make(map[string]bool)
			packages[cve] = make(map[string]bool)
		}
		if severityRank(item.Severity) > severityRank(vulnerability.Severity) {
			vulnerability.Severity = item.Severity
		}
		hosts[cve][item.HostID] = true
		packages[cve][item.Package] = true
	}
	result := make([]Vulnerability, 0, len(byCVE))
	for cve, vulnerability := range byCVE {
		vulnerability.HostCount = len(hosts[cve])
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

func insertCheckResults(tx *sql.Tx, id string, report map[string]any, packageCounts SeverityCounts, packageFindings, unsupported int) error {
	for _, check := range reportChecks(report) {
		if check != CheckPackages {
			continue
		}
		status := "completed"
		if unsupported > 0 {
			status = "partial"
		}
		if _, err := tx.Exec(`INSERT INTO scan_checks (scan_id, check_id, status, finding_count, critical, high, medium, low, unknown)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, CheckPackages, status, packageFindings,
			packageCounts.Critical, packageCounts.High, packageCounts.Medium, packageCounts.Low, packageCounts.Unknown); err != nil {
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
	for _, finding := range findings {
		counts.add(finding.Severity)
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
	result, err := tx.Exec(`UPDATE scans SET status = ?, error = '', host_key_fingerprint = '', finished_at = ?, os = ?,
		finding_count = ?, unsupported_count = ?, critical = ?, high = ?, medium = ?, low = ?, unknown = ?,
		feed_stale = ?, report_json = ? WHERE id = ? AND status = ?`,
		ScanSucceeded, finishedAt, operatingSystem, len(findings), unsupported,
		counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown,
		feedStale, string(encoded), id, ScanRunning)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return err
	} else if changed != 1 {
		return fmt.Errorf("scan %s is not running", id)
	}
	if err := insertCheckResults(tx, id, report, counts, len(findings), unsupported); err != nil {
		return err
	}
	for _, finding := range findings {
		if _, err := tx.Exec(`INSERT INTO findings (scan_id, cve, package, installed_version, fixed_version, severity, url, title)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, finding.ID, finding.Package, finding.InstalledVersion,
			finding.FixedVersion, strings.ToUpper(finding.Severity), finding.URL, finding.Title); err != nil {
			return err
		}
	}
	return nil
}
