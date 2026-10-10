package store

import (
	"database/sql"
	"errors"
	"strings"
)

// metaServerHost holds the ID of the agent host that is the server's own
// machine.
const metaServerHost = "server_host_id"

// ThisServerHost returns the ID of the agent host that is the server's own
// machine, or "" when none is.
func ThisServerHost() (string, error) { return Meta(metaServerHost) }

// AdoptThisServer marks the agent host agentID as the server's own machine.
// A host registered earlier as "this machine", which the server scanned
// itself without root, is merged into it: its scans, log entries and
// schedules move to the agent host, and it is removed. merged reports whether
// there was one.
func AdoptThisServer(agentID string) (merged bool, err error) {
	host, err := GetHost(agentID)
	if err != nil {
		return false, err
	}
	if host.Transport != TransportAgent {
		return false, errors.New("only an agent host can be the server's own machine")
	}
	db, err := database()
	if err != nil {
		return false, err
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var localID string
	switch err := tx.QueryRow("SELECT id FROM hosts WHERE transport = ?", TransportLocal).Scan(&localID); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		for _, statement := range []string{
			"UPDATE scans SET host_id = ? WHERE host_id = ?",
			"UPDATE logs SET host_id = ? WHERE host_id = ?",
		} {
			if _, err := tx.Exec(statement, agentID, localID); err != nil {
				return false, err
			}
		}
		rows, err := tx.Query("SELECT id, host_ids FROM schedules WHERE host_ids LIKE ?", "%,"+localID+",%")
		if err != nil {
			return false, err
		}
		updates := map[string]string{}
		for rows.Next() {
			var id, hosts string
			if err := rows.Scan(&id, &hosts); err != nil {
				rows.Close()
				return false, err
			}
			moved := strings.ReplaceAll(hosts, ","+localID+",", ","+agentID+",")
			// A schedule that named both keeps the agent host once.
			updates[id] = encodeChecks(decodeUnique(moved))
		}
		rows.Close()
		for id, hosts := range updates {
			if _, err := tx.Exec("UPDATE schedules SET host_ids = ? WHERE id = ?", hosts, id); err != nil {
				return false, err
			}
		}
		if _, err := tx.Exec("DELETE FROM hosts WHERE id = ?", localID); err != nil {
			return false, err
		}
		merged = true
	}
	if _, err := tx.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
		metaServerHost, agentID); err != nil {
		return false, err
	}
	return merged, tx.Commit()
}

func decodeUnique(encoded string) []string {
	seen := map[string]bool{}
	values := make([]string, 0)
	for _, value := range decodeChecks(encoded) {
		if !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}
