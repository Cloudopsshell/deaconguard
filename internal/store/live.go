package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/agentversion"
	"deaconguard/internal/live"
)

// Live detection's states beyond the agent's own (live.State*): the agent
// is too old to run it, the server hasn't heard from it yet, or it stopped
// reporting.
const (
	LiveAgentTooOld = "agent_too_old"
	LiveWaiting     = "waiting"
)

// LiveStoppedReporting is the reason detection counts as stopped when the
// agent stopped reporting.
const LiveStoppedReporting = "the agent stopped reporting"

// liveQuiet is how long an agent may go without reporting before its
// detection counts as stopped: a few of its 15-second reports.
const liveQuiet = 2 * time.Minute

// KeepLiveAlerts bounds the alerts kept per host; older than keepLiveDays
// days go too.
const (
	KeepLiveAlerts = 5000
	keepLiveDays   = 30
)

// LiveStatus is a host's live detection as the dashboard shows it.
type LiveStatus struct {
	live.Status
	Enabled bool `json:"enabled"`
	// UpdatedAt is when the agent last reported.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Alerts24h counts the last day's alerts by severity, tests left out.
	Alerts24h SeverityCounts `json:"alerts_24h"`
	// Nodes and NodesActive count, for a cluster, its nodes' agents and how
	// many of them have detection active.
	Nodes       int `json:"nodes,omitempty"`
	NodesActive int `json:"nodes_active,omitempty"`
}

// LiveAlert is one stored alert.
type LiveAlert struct {
	ID     int64     `json:"id"`
	HostID string    `json:"host_id"`
	At     time.Time `json:"at"`
	live.Alert
}

// SaveLiveReport records an agent's report and returns the state it was in
// before, so a change can be notified. Alerts get the time they arrived.
func SaveLiveReport(hostID string, status live.Status, alerts []live.Alert, now time.Time) (previous string, err error) {
	db, err := database()
	if err != nil {
		return "", err
	}
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := tx.QueryRow("SELECT state FROM live_status WHERE host_id = ?", hostID).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if status.State != "" {
		if _, err := tx.Exec(`INSERT INTO live_status (host_id, state, reason, since, kernel, events_last_hour, lost, suppressed, cpu_percent, memory_bytes, test_error, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (host_id) DO UPDATE SET state = excluded.state, reason = excluded.reason, since = excluded.since, kernel = excluded.kernel,
				events_last_hour = excluded.events_last_hour, lost = excluded.lost, suppressed = excluded.suppressed, cpu_percent = excluded.cpu_percent,
				memory_bytes = excluded.memory_bytes, test_error = excluded.test_error, updated_at = excluded.updated_at`,
			hostID, limit(status.State, 32), limit(status.Reason, 500), status.Since.UTC().Format(time.RFC3339), limit(status.Kernel, 100),
			status.EventsLastHour, status.Lost, status.Suppressed, status.CPUPercent, status.MemoryBytes, limit(status.TestError, 500),
			now.UTC().Format(time.RFC3339)); err != nil {
			return "", err
		}
	}
	for _, alert := range alerts {
		if _, err := tx.Exec(`INSERT INTO live_alerts (host_id, at, rule, severity, title, detail, pid, user, program, parent, command, path, test, repeats)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			hostID, now.UTC().Format(time.RFC3339Nano), limit(alert.Rule, 20), limit(strings.ToUpper(alert.Severity), 10), limit(alert.Title, 300),
			limit(alert.Detail, 2000), alert.PID, limit(alert.User, 100), limit(alert.Program, 512), limit(alert.Parent, 100),
			limit(alert.Command, 600), limit(alert.Path, 512), alert.Test, alert.Repeats); err != nil {
			return "", err
		}
	}
	if len(alerts) > 0 {
		if _, err := tx.Exec(`DELETE FROM live_alerts WHERE host_id = ? AND (at < ? OR id <= (SELECT id FROM live_alerts WHERE host_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?))`,
			hostID, now.Add(-keepLiveDays*24*time.Hour).UTC().Format(time.RFC3339Nano), hostID, KeepLiveAlerts); err != nil {
			return "", err
		}
	}
	return previous, tx.Commit()
}

func limit(text string, size int) string {
	if len(text) > size {
		return text[:size]
	}
	return text
}

// LiveSettings is whether live detection runs on a host and whether a test
// alert is waiting to be asked for.
func LiveSettings(hostID string) (enabled, test bool, err error) {
	db, err := database()
	if err != nil {
		return false, false, err
	}
	err = db.QueryRow("SELECT live_enabled, live_test FROM hosts WHERE id = ?", hostID).Scan(&enabled, &test)
	return enabled, test, err
}

// SetLiveEnabled turns live detection on or off for a host.
func SetLiveEnabled(hostID string, enabled bool) error {
	return updateHostLive("UPDATE hosts SET live_enabled = ? WHERE id = ?", enabled, hostID)
}

// AskLiveTest has the host's agent send a test alert with its next report;
// TakeLiveTest clears the request as the agent is told.
func AskLiveTest(hostID string) error {
	return updateHostLive("UPDATE hosts SET live_test = ? WHERE id = ?", true, hostID)
}

func TakeLiveTest(hostID string) error {
	return updateHostLive("UPDATE hosts SET live_test = ? WHERE id = ?", false, hostID)
}

func updateHostLive(query string, value bool, hostID string) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec(query, value, hostID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return fmt.Errorf("unknown host ID: %s", hostID)
	}
	return nil
}

// LiveAlerts lists a host's alerts, newest first, at most limit of them.
func LiveAlerts(hostID string, count int) ([]LiveAlert, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT id, host_id, at, rule, severity, title, detail, pid, user, program, parent, command, path, test, repeats
		FROM live_alerts WHERE host_id = ? ORDER BY id DESC LIMIT ?`, hostID, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts := []LiveAlert{}
	for rows.Next() {
		var alert LiveAlert
		var at string
		if err := rows.Scan(&alert.ID, &alert.HostID, &at, &alert.Rule, &alert.Severity, &alert.Title, &alert.Detail, &alert.PID, &alert.User,
			&alert.Program, &alert.Parent, &alert.Command, &alert.Path, &alert.Test, &alert.Repeats); err != nil {
			return nil, err
		}
		alert.At, _ = time.Parse(time.RFC3339Nano, at)
		alerts = append(alerts, alert)
	}
	return alerts, rows.Err()
}

// liveStatuses reads every host's live detection, as HostSummaries shows
// it, and works out the state the dashboard shows from the agent's report,
// its version, the host's setting and how recently it reported.
func liveStatuses(hosts []Host, agents map[string]Agent, now time.Time) (map[string]*LiveStatus, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	enabled := map[string]bool{}
	rows, err := db.Query("SELECT id, live_enabled FROM hosts")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var on bool
		if err := rows.Scan(&id, &on); err != nil {
			rows.Close()
			return nil, err
		}
		enabled[id] = on
	}
	rows.Close()
	reported := map[string]LiveStatus{}
	rows, err = db.Query(`SELECT host_id, state, reason, since, kernel, events_last_hour, lost, suppressed, cpu_percent, memory_bytes, test_error, updated_at FROM live_status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status LiveStatus
		var hostID, since, updated string
		if err := rows.Scan(&hostID, &status.State, &status.Reason, &since, &status.Kernel, &status.EventsLastHour, &status.Lost, &status.Suppressed,
			&status.CPUPercent, &status.MemoryBytes, &status.TestError, &updated); err != nil {
			rows.Close()
			return nil, err
		}
		status.Since, _ = time.Parse(time.RFC3339, since)
		if at, err := time.Parse(time.RFC3339, updated); err == nil {
			status.UpdatedAt = &at
		}
		reported[hostID] = status
	}
	rows.Close()
	counts := map[string]SeverityCounts{}
	rows, err = db.Query(`SELECT host_id, severity, COUNT(*) FROM live_alerts WHERE test = 0 AND at >= ? GROUP BY host_id, severity`,
		now.Add(-24*time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hostID, severity string
		var count int
		if err := rows.Scan(&hostID, &severity, &count); err != nil {
			rows.Close()
			return nil, err
		}
		tally := counts[hostID]
		for range count {
			tally.add(severity)
		}
		counts[hostID] = tally
	}
	rows.Close()
	statuses := map[string]*LiveStatus{}
	for _, host := range hosts {
		agent, isAgent := agents[host.ID]
		if !isAgent || host.IsCluster() {
			continue
		}
		status := reported[host.ID]
		status.Enabled = enabled[host.ID]
		status.Alerts24h = counts[host.ID]
		switch {
		case !agentversion.SupportsLive(agent.Version):
			status.State, status.Reason = LiveAgentTooOld, "the agent runs "+agent.Version+"; live detection needs 1.27.0 or later"
		case !status.Enabled:
			status.State, status.Reason = live.StateOff, "turned off on the dashboard"
		case status.UpdatedAt == nil:
			status.State, status.Reason = LiveWaiting, "waiting for the agent's first report"
		case now.Sub(*status.UpdatedAt) > liveQuiet && status.State != live.StateUnsupported:
			status.State, status.Reason, status.Since = live.StateStopped, LiveStoppedReporting, *status.UpdatedAt
		}
		statuses[host.ID] = &status
	}
	// A cluster counts its nodes'.
	for _, host := range hosts {
		if !host.IsCluster() {
			continue
		}
		cluster := &LiveStatus{Enabled: true}
		for _, node := range hosts {
			if node.ClusterID != host.ID || statuses[node.ID] == nil {
				continue
			}
			cluster.Nodes++
			if statuses[node.ID].State == live.StateActive {
				cluster.NodesActive++
			}
			alerts := statuses[node.ID].Alerts24h
			cluster.Alerts24h.Critical += alerts.Critical
			cluster.Alerts24h.High += alerts.High
			cluster.Alerts24h.Medium += alerts.Medium
			cluster.Alerts24h.Low += alerts.Low
		}
		if cluster.Nodes > 0 {
			cluster.State = live.StateActive
			if cluster.NodesActive < cluster.Nodes {
				cluster.State = live.StateStopped
				cluster.Reason = "live detection runs on " + plural(cluster.NodesActive, "node") + " of " + plural(cluster.Nodes, "node")
			}
			statuses[host.ID] = cluster
		}
	}
	return statuses, nil
}

func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(count) + " " + noun + "s"
}

// HostLive is one host's live detection, as HostSummaries shows it, or nil
// for a host without an agent or a cluster without node agents.
func HostLive(hostID string) (*LiveStatus, error) {
	hosts, err := ListHosts()
	if err != nil {
		return nil, err
	}
	agents, err := Agents()
	if err != nil {
		return nil, err
	}
	statuses, err := liveStatuses(hosts, agents, time.Now())
	if err != nil {
		return nil, err
	}
	return statuses[hostID], nil
}
