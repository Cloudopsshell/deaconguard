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
	ID       string `json:"id"`
	Address  string `json:"address"`
	Username string `json:"username"`
	// AllowSudo lets deeper checks run fixed read-only commands through sudo.
	AllowSudo bool `json:"allow_sudo"`
	// Transport is how DeaconGuard reaches the host.
	Transport string `json:"transport"`
}

const (
	// TransportLocal is the machine DeaconGuard runs on; Address holds its
	// hostname and Username the account that runs the scans.
	TransportLocal = "local"
	// TransportAgent is a machine running `deaconguard agent`, enrolled with a
	// one-time token; Address holds the hostname the agent reported.
	TransportAgent = "agent"
	// TransportSSH marks hosts registered before SSH scanning was removed in
	// 0.2.0. They keep their scan history but can no longer be scanned.
	TransportSSH = "ssh"
)

// Scannable reports whether DeaconGuard can still scan the host.
func (h Host) Scannable() bool { return h.Transport == TransportLocal || h.Transport == TransportAgent }

const databaseName = "deaconguard.db"

var (
	databasesMu sync.Mutex
	databases   = make(map[string]*sql.DB)
)

// SystemDataDir is the deaconguard-server service's data directory. It is owned
// by the deaconguard system user the service runs as.
const SystemDataDir = "/var/lib/deaconguard"

// Before 0.3.0 DeaconGuard was called OpsArmor. Its data directory, database
// file, and OPSARMOR_HOME variable are still found and moved to the new names.
const (
	legacyName         = "opsarmor"
	legacyDatabaseName = "opsarmor.db"
)

// configuredHome is $DEACONGUARD_HOME, or $OPSARMOR_HOME from before the rename.
func configuredHome() string {
	if configured := os.Getenv("DEACONGUARD_HOME"); configured != "" {
		return configured
	}
	return os.Getenv("OPSARMOR_HOME")
}

// DataDir is $DEACONGUARD_HOME if set; SystemDataDir for the account that owns
// it, such as the service's; otherwise ~/.local/share/deaconguard.
func DataDir() string {
	if configured := configuredHome(); configured != "" {
		return configured
	}
	if info, err := os.Stat(SystemDataDir); err == nil {
		if owner, ok := fileOwner(info); ok && owner == os.Geteuid() {
			return SystemDataDir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".local", "share", "deaconguard")
	}
	return filepath.Join(home, ".local", "share", "deaconguard")
}

// adoptLegacyData moves data kept under the OpsArmor names into directory: the
// ~/.local/share/opsarmor directory when directory is its default successor,
// and opsarmor.db with its WAL files inside directory.
func adoptLegacyData(directory string) error {
	if configuredHome() == "" {
		legacy := filepath.Join(filepath.Dir(directory), legacyName)
		if filepath.Base(directory) == "deaconguard" && directory != SystemDataDir {
			if _, err := os.Stat(directory); errors.Is(err, os.ErrNotExist) {
				if info, err := os.Stat(legacy); err == nil && info.IsDir() {
					if err := os.Rename(legacy, directory); err != nil {
						return err
					}
				}
			}
		}
	}
	current := filepath.Join(directory, databaseName)
	if _, err := os.Stat(current); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	old := filepath.Join(directory, legacyDatabaseName)
	if _, err := os.Stat(old); err != nil {
		return nil
	}
	// The WAL and shared-memory files belong to the database and move with it.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Rename(old+suffix, current+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(old, current)
}

func DatabasePath() string { return filepath.Join(DataDir(), databaseName) }

// ErrServiceData is returned when root runs a command that would change the
// server's data, which must stay owned by the service account.
var ErrServiceData = errors.New("the DeaconGuard server's data belongs to the deaconguard user; run this command as that user, for example: sudo -u deaconguard deaconguard user add admin")

// database returns a shared connection for the current data directory, creating
// the schema and importing JSON profiles and reports from earlier releases once.
func database() (*sql.DB, error) {
	if configuredHome() == "" && os.Geteuid() == 0 {
		// Root would otherwise quietly use a separate database under its own
		// home directory instead of the server's.
		if info, err := os.Stat(SystemDataDir); err == nil {
			if owner, ok := fileOwner(info); ok && owner != 0 {
				return nil, ErrServiceData
			}
		}
	}
	path := DatabasePath()
	databasesMu.Lock()
	defer databasesMu.Unlock()
	if db, ok := databases[path]; ok {
		return db, nil
	}
	if err := adoptLegacyData(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("move OpsArmor data to %s: %w", filepath.Dir(path), err)
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
		return nil, fmt.Errorf("prepare DeaconGuard database: %w", err)
	}
	if err := importLegacy(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("import earlier DeaconGuard data: %w", err)
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
	if version < 5 {
		if err := execInTx(db, schemaV5); err != nil {
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

// schemaV4 records how each host is reached; hosts from earlier versions were
// all SSH hosts, which 0.2.0 keeps for their history but no longer scans.
const schemaV4 = `
ALTER TABLE hosts ADD COLUMN transport TEXT NOT NULL DEFAULT 'ssh';
PRAGMA user_version = 4;`

// schemaV5 adds the network server: dashboard accounts and their sessions, an
// audit log, one-time enrollment tokens, and enrolled agents. Secrets are
// stored only as SHA-256 hashes, passwords as PBKDF2 hashes.
const schemaV5 = `
CREATE TABLE users (
	id            TEXT PRIMARY KEY,
	username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	created_at    TEXT NOT NULL
);
CREATE TABLE sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
CREATE TABLE audit_log (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	at     TEXT NOT NULL,
	actor  TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	remote TEXT NOT NULL DEFAULT ''
);
CREATE TABLE enrollment_tokens (
	id          TEXT PRIMARY KEY,
	secret_hash TEXT NOT NULL UNIQUE,
	server_url  TEXT NOT NULL,
	created_by  TEXT NOT NULL,
	created_at  TEXT NOT NULL,
	expires_at  TEXT NOT NULL,
	used_at     TEXT,
	host_id     TEXT,
	revoked_at  TEXT
);
CREATE TABLE agents (
	host_id         TEXT PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
	credential_hash TEXT NOT NULL,
	enrolled_at     TEXT NOT NULL,
	last_seen_at    TEXT NOT NULL,
	version         TEXT NOT NULL DEFAULT '',
	os              TEXT NOT NULL DEFAULT '',
	remote          TEXT NOT NULL DEFAULT ''
);
PRAGMA user_version = 5;`

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
		// Profiles from before the database were all SSH hosts.
		var hosts []struct {
			ID       string  `json:"id"`
			Address  string  `json:"address"`
			Username string  `json:"username"`
			Port     int     `json:"port"`
			KeyPath  *string `json:"key_path"`
		}
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
	rows, err := db.Query("SELECT id, address, username, allow_sudo, transport FROM hosts ORDER BY created_at, rowid")
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
	if err := row.Scan(&host.ID, &host.Address, &host.Username, &host.AllowSudo, &host.Transport); err != nil {
		return Host{}, err
	}
	return host, nil
}

// ErrLocalHostExists is returned when this machine is already registered.
var ErrLocalHostExists = errors.New("this machine is already registered as a host")

// AddLocalHost registers the machine DeaconGuard runs on. hostname and username
// describe it; scans run as the user running DeaconGuard.
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
	// port and key_path only described SSH hosts and are left empty.
	_, err := db.Exec(`INSERT INTO hosts (id, address, username, port, transport, created_at) VALUES (?, ?, ?, 0, ?, ?)`,
		host.ID, host.Address, host.Username, host.Transport, nowText())
	return err
}

func GetHost(id string) (Host, error) {
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	host, err := scanHost(db.QueryRow("SELECT id, address, username, allow_sudo, transport FROM hosts WHERE id = ?", id))
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

// RemoveHost deletes a host; its scans are kept. Removing an agent host also
// revokes the agent's credential and cancels its queued scans.
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
	if _, err := db.Exec("UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE host_id = ? AND status = ?",
		ScanFailed, "the host was removed before its agent picked up the scan", nowText(), id, ScanQueued); err != nil {
		return Host{}, err
	}
	return host, nil
}

// Meta returns a stored setting, or "" if it is not set.
func Meta(key string) (string, error) {
	db, err := database()
	if err != nil {
		return "", err
	}
	var value string
	err = db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func SetMeta(key, value string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, value)
	return err
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
