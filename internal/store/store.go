package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Host struct {
	ID       string  `json:"id"`
	Address  string  `json:"address"`
	Username string  `json:"username"`
	Port     int     `json:"port"`
	KeyPath  *string `json:"key_path"`
	// AllowSudo lets deeper checks run fixed read-only commands through sudo.
	AllowSudo bool `json:"allow_sudo"`
	// Transport is how OpsArmor reaches the host: TransportSSH or TransportLocal.
	Transport string `json:"transport"`
}

const (
	TransportSSH = "ssh"
	// TransportLocal is the machine OpsArmor runs on; Address holds its
	// hostname and Username the account that runs the scans.
	TransportLocal = "local"
)

const databaseName = "opsarmor.db"

var (
	databasesMu sync.Mutex
	databases   = make(map[string]*sql.DB)
)

func DataDir() string {
	if configured := os.Getenv("OPSARMOR_HOME"); configured != "" {
		return configured
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".local", "share", "opsarmor")
	}
	return filepath.Join(home, ".local", "share", "opsarmor")
}

func KnownHostsPath() string { return filepath.Join(DataDir(), "known_hosts") }

func DatabasePath() string { return filepath.Join(DataDir(), databaseName) }

// database returns a shared connection for the current data directory, creating
// the schema and importing JSON profiles and reports from earlier releases once.
func database() (*sql.DB, error) {
	path := DatabasePath()
	databasesMu.Lock()
	defer databasesMu.Unlock()
	if db, ok := databases[path]; ok {
		return db, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// SQLite gives the WAL and shared-memory files the database file's mode,
	// so creating it owner-only first keeps all three private.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare OpsArmor database: %w", err)
	}
	if err := importLegacy(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("import earlier OpsArmor data: %w", err)
	}
	databases[path] = db
	return db, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version < 1 {
		if _, err := db.Exec(schemaV1); err != nil {
			return err
		}
	}
	if version < 2 {
		if err := execInTx(db, schemaV2); err != nil {
			return err
		}
	}
	if version < 3 {
		if err := execInTx(db, schemaV3); err != nil {
			return err
		}
	}
	if version < 4 {
		if err := execInTx(db, schemaV4); err != nil {
			return err
		}
	}
	return nil
}

func execInTx(db *sql.DB, statements string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(statements); err != nil {
		return err
	}
	return tx.Commit()
}

const schemaV1 = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
	id         TEXT PRIMARY KEY,
	address    TEXT NOT NULL,
	username   TEXT NOT NULL,
	port       INTEGER NOT NULL,
	key_path   TEXT,
	created_at TEXT NOT NULL
);
-- Scans keep host_id and address without a foreign key so reports survive host removal.
CREATE TABLE IF NOT EXISTS scans (
	id                   TEXT PRIMARY KEY,
	host_id              TEXT NOT NULL,
	address              TEXT NOT NULL,
	status               TEXT NOT NULL,
	error                TEXT NOT NULL DEFAULT '',
	host_key_fingerprint TEXT NOT NULL DEFAULT '',
	started_at           TEXT NOT NULL,
	finished_at          TEXT,
	os                   TEXT NOT NULL DEFAULT '',
	finding_count        INTEGER NOT NULL DEFAULT 0,
	unsupported_count    INTEGER NOT NULL DEFAULT 0,
	critical             INTEGER NOT NULL DEFAULT 0,
	high                 INTEGER NOT NULL DEFAULT 0,
	medium               INTEGER NOT NULL DEFAULT 0,
	low                  INTEGER NOT NULL DEFAULT 0,
	unknown              INTEGER NOT NULL DEFAULT 0,
	feed_stale           INTEGER NOT NULL DEFAULT 0,
	report_json          TEXT
);
CREATE INDEX IF NOT EXISTS scans_by_host ON scans (host_id, started_at DESC);
CREATE TABLE IF NOT EXISTS findings (
	scan_id           TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
	cve               TEXT NOT NULL,
	package           TEXT NOT NULL,
	installed_version TEXT NOT NULL,
	fixed_version     TEXT NOT NULL,
	severity          TEXT NOT NULL,
	url               TEXT NOT NULL,
	title             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_by_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_by_cve ON findings (cve);
PRAGMA user_version = 1;`

// schemaV2 adds per-host sudo consent and scans made of several checks.
// Scans stored before it only ran the package vulnerability check.
const schemaV2 = `
ALTER TABLE hosts ADD COLUMN allow_sudo INTEGER NOT NULL DEFAULT 0;
-- Comma-delimited on both ends so a check can be matched with LIKE '%,id,%'.
ALTER TABLE scans ADD COLUMN checks TEXT NOT NULL DEFAULT ',packages,';
CREATE TABLE scan_checks (
	scan_id       TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
	check_id      TEXT NOT NULL,
	status        TEXT NOT NULL,
	privileged    INTEGER NOT NULL DEFAULT 0,
	summary       TEXT NOT NULL DEFAULT '',
	notes         TEXT NOT NULL DEFAULT '[]',
	error         TEXT NOT NULL DEFAULT '',
	finding_count INTEGER NOT NULL DEFAULT 0,
	critical      INTEGER NOT NULL DEFAULT 0,
	high          INTEGER NOT NULL DEFAULT 0,
	medium        INTEGER NOT NULL DEFAULT 0,
	low           INTEGER NOT NULL DEFAULT 0,
	unknown       INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (scan_id, check_id)
);
CREATE TABLE check_findings (
	scan_id  TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
	check_id TEXT NOT NULL,
	rule     TEXT NOT NULL,
	severity TEXT NOT NULL,
	title    TEXT NOT NULL,
	detail   TEXT NOT NULL,
	evidence TEXT NOT NULL
);
CREATE INDEX check_findings_by_scan ON check_findings (scan_id, check_id);
INSERT INTO scan_checks (scan_id, check_id, status, finding_count, critical, high, medium, low, unknown)
	SELECT id, 'packages', CASE WHEN unsupported_count > 0 THEN 'partial' ELSE 'completed' END,
		finding_count, critical, high, medium, low, unknown
	FROM scans WHERE status = 'succeeded';
PRAGMA user_version = 2;`

// schemaV3 keeps each scan's activity log so it can be replayed later.
const schemaV3 = `
ALTER TABLE scans ADD COLUMN events_json TEXT;
PRAGMA user_version = 3;`

// schemaV4 records how each host is reached; existing hosts use SSH.
const schemaV4 = `
ALTER TABLE hosts ADD COLUMN transport TEXT NOT NULL DEFAULT 'ssh';
PRAGMA user_version = 4;`

// importLegacy copies hosts.json and reports/*.json from the file-based store
// into the database once. The original files are left untouched.
func importLegacy(db *sql.DB) error {
	var done string
	err := db.QueryRow("SELECT value FROM meta WHERE key = 'legacy_import'").Scan(&done)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	contents, err := os.ReadFile(filepath.Join(DataDir(), "hosts.json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		var hosts []Host
		if err := json.Unmarshal(contents, &hosts); err != nil {
			return fmt.Errorf("read host profiles: %w", err)
		}
		now := nowText()
		for _, host := range hosts {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO hosts (id, address, username, port, key_path, created_at)
				VALUES (?, ?, ?, ?, ?, ?)`, host.ID, host.Address, host.Username, host.Port, host.KeyPath, now); err != nil {
				return err
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(DataDir(), "reports"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !validID(id) {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(DataDir(), "reports", entry.Name()))
		if err != nil {
			return err
		}
		var report map[string]any
		if err := json.Unmarshal(contents, &report); err != nil {
			// An unreadable legacy report stays on disk; it must not block the rest.
			continue
		}
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM scans WHERE id = ?", id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if err := insertReport(tx, id, report); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec("INSERT INTO meta (key, value) VALUES ('legacy_import', ?)", nowText()); err != nil {
		return err
	}
	return tx.Commit()
}

func ListHosts() ([]Host, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT id, address, username, port, key_path, allow_sudo, transport FROM hosts ORDER BY created_at, rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hosts := make([]Host, 0)
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

type rowScanner interface {
	Scan(destinations ...any) error
}

func scanHost(row rowScanner) (Host, error) {
	var host Host
	var keyPath sql.NullString
	if err := row.Scan(&host.ID, &host.Address, &host.Username, &host.Port, &keyPath, &host.AllowSudo, &host.Transport); err != nil {
		return Host{}, err
	}
	if keyPath.Valid {
		value := keyPath.String
		host.KeyPath = &value
	}
	return host, nil
}

func AddHost(address, username string, port int, keyPath *string) (Host, error) {
	if strings.TrimSpace(address) == "" || strings.ContainsAny(address, " \t\r\n") ||
		strings.TrimSpace(username) == "" || strings.ContainsAny(username, " \t\r\n") {
		return Host{}, fmt.Errorf("a host address and SSH username without whitespace are required")
	}
	if port < 1 || port > 65535 {
		return Host{}, fmt.Errorf("SSH port must be between 1 and 65535")
	}
	if keyPath != nil {
		if _, err := os.Stat(expandHome(*keyPath)); err != nil {
			return Host{}, fmt.Errorf("SSH private key file does not exist")
		}
	}
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	id, err := newID()
	if err != nil {
		return Host{}, err
	}
	host := Host{ID: id, Address: address, Username: username, Port: port, KeyPath: keyPath, Transport: TransportSSH}
	if err := insertHost(db, host); err != nil {
		return Host{}, err
	}
	return host, nil
}

// ErrLocalHostExists is returned when this machine is already registered.
var ErrLocalHostExists = errors.New("this machine is already registered as a host")

// AddLocalHost registers the machine OpsArmor runs on. hostname and username
// describe it; scans run as the user running OpsArmor.
func AddLocalHost(hostname, username string) (Host, error) {
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	var existing int
	if err := db.QueryRow("SELECT COUNT(*) FROM hosts WHERE transport = ?", TransportLocal).Scan(&existing); err != nil {
		return Host{}, err
	}
	if existing > 0 {
		return Host{}, ErrLocalHostExists
	}
	id, err := newID()
	if err != nil {
		return Host{}, err
	}
	host := Host{ID: id, Address: hostname, Username: username, Transport: TransportLocal}
	if err := insertHost(db, host); err != nil {
		return Host{}, err
	}
	return host, nil
}

func insertHost(db *sql.DB, host Host) error {
	_, err := db.Exec(`INSERT INTO hosts (id, address, username, port, key_path, transport, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		host.ID, host.Address, host.Username, host.Port, host.KeyPath, host.Transport, nowText())
	return err
}

func GetHost(id string) (Host, error) {
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	host, err := scanHost(db.QueryRow("SELECT id, address, username, port, key_path, allow_sudo, transport FROM hosts WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, fmt.Errorf("unknown host ID: %s", id)
	}
	return host, err
}

// SetAllowSudo records whether deeper checks may use sudo on a host.
func SetAllowSudo(id string, allow bool) (Host, error) {
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	result, err := db.Exec("UPDATE hosts SET allow_sudo = ? WHERE id = ?", allow, id)
	if err != nil {
		return Host{}, err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return Host{}, err
	} else if changed == 0 {
		return Host{}, fmt.Errorf("unknown host ID: %s", id)
	}
	return GetHost(id)
}

func RemoveHost(id string) (Host, error) {
	host, err := GetHost(id)
	if err != nil {
		return Host{}, err
	}
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	if _, err := db.Exec("DELETE FROM hosts WHERE id = ?", id); err != nil {
		return Host{}, err
	}
	return host, nil
}

func TrustHostKey(host Host, knownHostsLine string) error {
	fields := strings.Fields(knownHostsLine)
	if len(fields) < 3 {
		return fmt.Errorf("invalid SSH known-host entry")
	}
	address := host.Address
	if host.Port != 22 {
		address = fmt.Sprintf("[%s]:%d", address, host.Port)
	}
	if fields[0] != address {
		return fmt.Errorf("SSH known-host entry does not match %s", address)
	}
	path := KnownHostsPath()
	contents, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	algorithmPinned := false
	for _, existing := range strings.Split(string(contents), "\n") {
		existingFields := strings.Fields(existing)
		if len(existingFields) < 3 || existingFields[0] != address || existingFields[1] != fields[1] {
			continue
		}
		algorithmPinned = true
		if strings.Join(existingFields[:3], " ") == strings.Join(fields[:3], " ") {
			return nil
		}
	}
	if algorithmPinned {
		return fmt.Errorf("a different SSH host key using %s is already trusted for %s", fields[1], address)
	}
	if err := os.MkdirAll(DataDir(), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := fmt.Fprintln(file, strings.Join(fields[:3], " ")); err != nil {
		return err
	}
	return file.Sync()
}

// SaveReport stores a completed CLI scan report and returns it with its report_id.
func SaveReport(report map[string]any) (map[string]any, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := insertReport(tx, id, report); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if hostID, _ := report["host_id"].(string); hostID != "" {
		if _, err := PruneScans(hostID, KeepScansPerHost); err != nil {
			return nil, err
		}
	}
	return withReportID(report, id), nil
}

func GetReport(id string) (map[string]any, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid report ID")
	}
	db, err := database()
	if err != nil {
		return nil, err
	}
	var status string
	var contents sql.NullString
	err = db.QueryRow("SELECT status, report_json FROM scans WHERE id = ?", id).Scan(&status, &contents)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("report not found")
	}
	if err != nil {
		return nil, err
	}
	if status != ScanSucceeded || !contents.Valid {
		return nil, fmt.Errorf("scan %s did not produce a report (status %s)", id, status)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(contents.String), &report); err != nil {
		return nil, fmt.Errorf("read scan report: %w", err)
	}
	report["report_id"] = id
	return report, nil
}

func withReportID(report map[string]any, id string) map[string]any {
	result := make(map[string]any, len(report)+1)
	result["report_id"] = id
	for key, value := range report {
		result[key] = value
	}
	return result
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return hex.EncodeToString(value), nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func nowText() string { return time.Now().UTC().Format(time.RFC3339) }

func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
}
