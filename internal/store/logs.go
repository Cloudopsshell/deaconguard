package store

import (
	"database/sql"
	"strings"
	"time"
)

// Where a log entry comes from.
const (
	LogServer = "server"
	LogAgent  = "agent"
)

// Log levels, from the least to the most severe.
const (
	LogInfo    = "info"
	LogWarning = "warning"
	LogError   = "error"
)

const (
	// keepLogs is how long log entries are kept.
	keepLogs = 7 * 24 * time.Hour
	// maxLogEntries bounds the log however busy the machines are.
	maxLogEntries = 100_000
	// maxLogMessage bounds one entry's message.
	maxLogMessage = 2000
)

// LogEntry is one line of the server's or an agent's log.
type LogEntry struct {
	ID      int64  `json:"id"`
	At      string `json:"at"`
	Source  string `json:"source"`
	HostID  string `json:"host_id,omitempty"`
	Host    string `json:"host,omitempty"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// LogLine is an entry to add. At is when it happened; zero means now.
type LogLine struct {
	At      time.Time
	Level   string
	Message string
}

// ValidLogLevel reports whether level is a log level.
func ValidLogLevel(level string) bool {
	return level == LogInfo || level == LogWarning || level == LogError
}

// Log adds an entry from source, about hostID if it is not "". It never fails
// what it records.
func Log(source, hostID, level, message string) {
	AddLogs(source, hostID, []LogLine{{Level: level, Message: message}})
}

// AddLogs adds entries from source about hostID, in order. Entries are
// cleaned: an unknown level becomes info, a long message is cut, and a time
// in the future or older than the log keeps becomes now.
func AddLogs(source, hostID string, lines []LogLine) error {
	if len(lines) == 0 {
		return nil
	}
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var last int64
	for _, line := range lines {
		at := line.At.UTC()
		if at.IsZero() || at.After(now.Add(5*time.Minute)) || at.Before(now.Add(-keepLogs)) {
			at = now
		}
		level := line.Level
		if !ValidLogLevel(level) {
			level = LogInfo
		}
		message := strings.ToValidUTF8(line.Message, "")
		if len(message) > maxLogMessage {
			message = strings.ToValidUTF8(message[:maxLogMessage], "") + "…"
		}
		result, err := tx.Exec("INSERT INTO logs (at, source, host_id, level, message) VALUES (?, ?, ?, ?, ?)",
			at.Format(time.RFC3339Nano), source, hostID, level, message)
		if err != nil {
			return err
		}
		last, _ = result.LastInsertId()
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Pruning every few hundred entries keeps inserts cheap.
	if last%200 < int64(len(lines)) {
		db.Exec("DELETE FROM logs WHERE id <= ? OR at < ?", last-maxLogEntries, now.Add(-keepLogs).Format(time.RFC3339Nano))
	}
	return nil
}

// LogQuery selects log entries. Empty fields match everything.
type LogQuery struct {
	Source string
	HostID string
	// Level is the least severe level included: warning means warnings and
	// errors.
	Level string
	// Search matches text in the message or the host's name.
	Search string
	// Before returns entries older than this ID, for the next page.
	Before int64
	Limit  int
}

// Logs returns matching entries, newest first, and whether there are more.
func Logs(query LogQuery) ([]LogEntry, bool, error) {
	db, err := database()
	if err != nil {
		return nil, false, err
	}
	if query.Limit <= 0 || query.Limit > 50_000 {
		query.Limit = 200
	}
	conditions := []string{"1 = 1"}
	var arguments []any
	if query.Source != "" {
		conditions = append(conditions, "logs.source = ?")
		arguments = append(arguments, query.Source)
	}
	if query.HostID != "" {
		conditions = append(conditions, "logs.host_id = ?")
		arguments = append(arguments, query.HostID)
	}
	switch query.Level {
	case LogWarning:
		conditions = append(conditions, "logs.level IN ('warning', 'error')")
	case LogError:
		conditions = append(conditions, "logs.level = 'error'")
	}
	if query.Search != "" {
		pattern := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query.Search) + "%"
		conditions = append(conditions, `(logs.message LIKE ? ESCAPE '\' OR COALESCE(hosts.address, '') LIKE ? ESCAPE '\')`)
		arguments = append(arguments, pattern, pattern)
	}
	if query.Before > 0 {
		conditions = append(conditions, "logs.id < ?")
		arguments = append(arguments, query.Before)
	}
	arguments = append(arguments, query.Limit+1)
	rows, err := db.Query(`SELECT logs.id, logs.at, logs.source, logs.host_id, COALESCE(hosts.address, ''), logs.level, logs.message
		FROM logs LEFT JOIN hosts ON hosts.id = logs.host_id
		WHERE `+strings.Join(conditions, " AND ")+` ORDER BY logs.id DESC LIMIT ?`, arguments...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	entries := make([]LogEntry, 0)
	for rows.Next() {
		var entry LogEntry
		if err := rows.Scan(&entry.ID, &entry.At, &entry.Source, &entry.HostID, &entry.Host, &entry.Level, &entry.Message); err != nil {
			return nil, false, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil && err != sql.ErrNoRows {
		return nil, false, err
	}
	more := len(entries) > query.Limit
	if more {
		entries = entries[:query.Limit]
	}
	return entries, more, nil
}
