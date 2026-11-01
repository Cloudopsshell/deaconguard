package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// NetworkTarget is a set of addresses, ranges and names the server scans
// for open ports, exposed services and TLS. IntervalHours 0 scans only on
// request; otherwise it is scanned that often. Latest is its newest scan.
type NetworkTarget struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Targets []string `json:"targets"`
	Ports   string   `json:"ports"`
	TLS     bool     `json:"tls"`
	// Web checks each web site a scan finds; WebPaths also asks for the
	// paths a site should never publish (1.25.0 and later).
	Web           bool         `json:"web"`
	WebPaths      bool         `json:"web_paths"`
	IntervalHours int          `json:"interval_hours"`
	CreatedBy     string       `json:"created_by"`
	CreatedAt     string       `json:"created_at"`
	Latest        *NetworkScan `json:"latest,omitempty"`
}

// NetworkScan is one scan of a target. Result is the netscan.Result as JSON.
type NetworkScan struct {
	ID         string          `json:"id"`
	TargetID   string          `json:"target_id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	Hosts      int             `json:"hosts"`
	OpenPorts  int             `json:"open_ports"`
	Severity   SeverityCounts  `json:"severity"`
	Result     json.RawMessage `json:"result,omitempty"`
	StartedBy  string          `json:"started_by"`
	StartedAt  string          `json:"started_at"`
	FinishedAt string          `json:"finished_at,omitempty"`
}

const keptNetworkScans = 20

var (
	ErrNetworkTargetNotFound = errors.New("unknown network target")
	ErrNetworkTargetExists   = errors.New("a network target with that name already exists")
	ErrNetworkScanNotFound   = errors.New("unknown network scan")
	ErrNetworkScanInProgress = errors.New("a scan of this target is already queued or running")
)

const networkTargetColumns = "id, name, targets, ports, tls, interval_hours, created_by, created_at, web, web_paths"

func scanNetworkTarget(row rowScanner) (NetworkTarget, error) {
	var target NetworkTarget
	var targets string
	if err := row.Scan(&target.ID, &target.Name, &targets, &target.Ports, &target.TLS, &target.IntervalHours, &target.CreatedBy, &target.CreatedAt, &target.Web, &target.WebPaths); err != nil {
		return NetworkTarget{}, err
	}
	target.Targets = splitList(targets)
	return target, nil
}

// NetworkTargets lists the targets by name, each with its latest scan.
func NetworkTargets() ([]NetworkTarget, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + networkTargetColumns + " FROM network_targets ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	list := make([]NetworkTarget, 0)
	for rows.Next() {
		target, err := scanNetworkTarget(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, target)
	}
	rows.Close()
	for index := range list {
		if list[index].Latest, err = latestNetworkScan(db, list[index].ID); err != nil {
			return nil, err
		}
	}
	return list, rows.Err()
}

// GetNetworkTarget returns one target with its latest scan.
func GetNetworkTarget(id string) (NetworkTarget, error) {
	db, err := database()
	if err != nil {
		return NetworkTarget{}, err
	}
	target, err := scanNetworkTarget(db.QueryRow("SELECT "+networkTargetColumns+" FROM network_targets WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return NetworkTarget{}, ErrNetworkTargetNotFound
	}
	if err != nil {
		return NetworkTarget{}, err
	}
	target.Latest, err = latestNetworkScan(db, id)
	return target, err
}

// SaveNetworkTarget adds a target without an ID, or replaces the one with
// its ID, and returns it as stored.
func SaveNetworkTarget(target NetworkTarget) (NetworkTarget, error) {
	db, err := database()
	if err != nil {
		return NetworkTarget{}, err
	}
	joined := strings.Join(target.Targets, ",")
	if target.ID == "" {
		if target.ID, err = newID(); err != nil {
			return NetworkTarget{}, err
		}
		_, err = db.Exec("INSERT INTO network_targets ("+networkTargetColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			target.ID, target.Name, joined, target.Ports, target.TLS, target.IntervalHours, target.CreatedBy, nowText(), target.Web, target.WebPaths)
	} else {
		var result sql.Result
		result, err = db.Exec("UPDATE network_targets SET name = ?, targets = ?, ports = ?, tls = ?, interval_hours = ?, web = ?, web_paths = ? WHERE id = ?",
			target.Name, joined, target.Ports, target.TLS, target.IntervalHours, target.Web, target.WebPaths, target.ID)
		if err == nil {
			if changed, _ := result.RowsAffected(); changed == 0 {
				return NetworkTarget{}, ErrNetworkTargetNotFound
			}
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return NetworkTarget{}, ErrNetworkTargetExists
		}
		return NetworkTarget{}, err
	}
	return GetNetworkTarget(target.ID)
}

// DeleteNetworkTarget removes a target and its scans, and returns it.
func DeleteNetworkTarget(id string) (NetworkTarget, error) {
	target, err := GetNetworkTarget(id)
	if err != nil {
		return NetworkTarget{}, err
	}
	db, err := database()
	if err != nil {
		return NetworkTarget{}, err
	}
	_, err = db.Exec("DELETE FROM network_targets WHERE id = ?", id)
	return target, err
}

const networkScanSummary = `id, target_id, status, error, hosts, open_ports, critical, high, medium, low, started_by, started_at, finished_at`

func scanNetworkScan(row rowScanner, withResult bool) (NetworkScan, error) {
	var scan NetworkScan
	var result string
	fields := []any{&scan.ID, &scan.TargetID, &scan.Status, &scan.Error, &scan.Hosts, &scan.OpenPorts,
		&scan.Severity.Critical, &scan.Severity.High, &scan.Severity.Medium, &scan.Severity.Low, &scan.StartedBy, &scan.StartedAt, &scan.FinishedAt}
	if withResult {
		fields = append(fields, &result)
	}
	if err := row.Scan(fields...); err != nil {
		return NetworkScan{}, err
	}
	if result != "" {
		scan.Result = json.RawMessage(result)
	}
	return scan, nil
}

func latestNetworkScan(db *sql.DB, targetID string) (*NetworkScan, error) {
	scan, err := scanNetworkScan(db.QueryRow("SELECT "+networkScanSummary+" FROM network_scans WHERE target_id = ? ORDER BY started_at DESC, rowid DESC LIMIT 1", targetID), false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// NetworkScans lists a target's scans, newest first, without results.
func NetworkScans(targetID string) ([]NetworkScan, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT "+networkScanSummary+" FROM network_scans WHERE target_id = ? ORDER BY started_at DESC, rowid DESC", targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := make([]NetworkScan, 0)
	for rows.Next() {
		scan, err := scanNetworkScan(rows, false)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

// GetNetworkScan returns one scan with its result.
func GetNetworkScan(id string) (NetworkScan, error) {
	db, err := database()
	if err != nil {
		return NetworkScan{}, err
	}
	scan, err := scanNetworkScan(db.QueryRow("SELECT "+networkScanSummary+", result FROM network_scans WHERE id = ?", id), true)
	if errors.Is(err, sql.ErrNoRows) {
		return NetworkScan{}, ErrNetworkScanNotFound
	}
	return scan, err
}

// QueueNetworkScan queues a scan of a target, unless one is queued or running.
func QueueNetworkScan(targetID, startedBy string) (NetworkScan, error) {
	db, err := database()
	if err != nil {
		return NetworkScan{}, err
	}
	id, err := newID()
	if err != nil {
		return NetworkScan{}, err
	}
	result, err := db.Exec(`INSERT INTO network_scans (id, target_id, status, started_by, started_at)
		SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM network_scans WHERE target_id = ? AND status IN ('queued', 'running'))`,
		id, targetID, ScanQueued, startedBy, nowText(), targetID)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return NetworkScan{}, ErrNetworkTargetNotFound
		}
		return NetworkScan{}, err
	}
	if added, _ := result.RowsAffected(); added == 0 {
		return NetworkScan{}, ErrNetworkScanInProgress
	}
	return GetNetworkScan(id)
}

// NextNetworkScan marks the oldest queued scan running and returns it.
func NextNetworkScan() (NetworkScan, bool, error) {
	db, err := database()
	if err != nil {
		return NetworkScan{}, false, err
	}
	for {
		scan, err := scanNetworkScan(db.QueryRow("SELECT "+networkScanSummary+" FROM network_scans WHERE status = ? ORDER BY started_at, rowid LIMIT 1", ScanQueued), false)
		if errors.Is(err, sql.ErrNoRows) {
			return NetworkScan{}, false, nil
		}
		if err != nil {
			return NetworkScan{}, false, err
		}
		result, err := db.Exec("UPDATE network_scans SET status = ? WHERE id = ? AND status = ?", ScanRunning, scan.ID, ScanQueued)
		if err != nil {
			return NetworkScan{}, false, err
		}
		if claimed, _ := result.RowsAffected(); claimed == 1 {
			scan.Status = ScanRunning
			return scan, true, nil
		}
	}
}

// FinishNetworkScan saves a succeeded scan, and keeps only the newest scans.
func FinishNetworkScan(scan NetworkScan) error {
	db, err := database()
	if err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE network_scans SET status = ?, hosts = ?, open_ports = ?, critical = ?, high = ?, medium = ?, low = ?,
		result = ?, finished_at = ? WHERE id = ?`, ScanSucceeded, scan.Hosts, scan.OpenPorts, scan.Severity.Critical, scan.Severity.High,
		scan.Severity.Medium, scan.Severity.Low, string(scan.Result), nowText(), scan.ID); err != nil {
		return err
	}
	return pruneNetworkScans(db, scan.TargetID)
}

// FailNetworkScan records why a scan failed.
func FailNetworkScan(id, message string) error {
	db, err := database()
	if err != nil {
		return err
	}
	var targetID string
	if err := db.QueryRow("SELECT target_id FROM network_scans WHERE id = ?", id).Scan(&targetID); err != nil {
		return err
	}
	if _, err := db.Exec("UPDATE network_scans SET status = ?, error = ?, finished_at = ? WHERE id = ?", ScanFailed, message, nowText(), id); err != nil {
		return err
	}
	return pruneNetworkScans(db, targetID)
}

// InterruptNetworkScans fails the scans that were running when the server stopped.
func InterruptNetworkScans() error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE network_scans SET status = ?, error = ?, finished_at = ? WHERE status = ?",
		ScanFailed, "The server stopped during this scan. Scan again.", nowText(), ScanRunning)
	return err
}

// DueNetworkTargets lists targets with an interval whose last scan started
// at least that long before now, or that were never scanned.
func DueNetworkTargets(now time.Time) ([]NetworkTarget, error) {
	all, err := NetworkTargets()
	if err != nil {
		return nil, err
	}
	var due []NetworkTarget
	for _, target := range all {
		if target.IntervalHours <= 0 {
			continue
		}
		if target.Latest == nil {
			due = append(due, target)
			continue
		}
		started, err := time.Parse(time.RFC3339, target.Latest.StartedAt)
		if err == nil && now.Sub(started) >= time.Duration(target.IntervalHours)*time.Hour {
			due = append(due, target)
		}
	}
	return due, nil
}

func pruneNetworkScans(db *sql.DB, targetID string) error {
	_, err := db.Exec(`DELETE FROM network_scans WHERE target_id = ? AND status NOT IN ('queued', 'running') AND id NOT IN (
		SELECT id FROM network_scans WHERE target_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?)`, targetID, targetID, keptNetworkScans)
	return err
}
