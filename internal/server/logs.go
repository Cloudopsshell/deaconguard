package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

// serverLog records what the server did in the dashboard's log, about hostID
// if it is not "", and in the service journal.
func serverLog(hostID, level, format string, arguments ...any) {
	message := fmt.Sprintf(format, arguments...)
	log.Print(message)
	store.Log(store.LogServer, hostID, level, message)
}

// logScanProblems records the warnings and errors a scan reported, such as a
// stale advisory feed or a check that was skipped or failed, once each. A
// check with partial coverage is not a problem to log: its result says so.
func logScanProblems(host store.Host, events []scan.Event) {
	seen := make(map[string]bool)
	for _, event := range events {
		level := map[string]string{"warning": store.LogWarning, "error": store.LogError}[event.Kind]
		message := event.Message
		switch event.Status {
		case "":
		case "skipped", "failed":
			message = fmt.Sprintf("the %s check %s: %s", event.Phase, event.Status, event.Message)
		default:
			continue
		}
		if level == "" || seen[message] {
			continue
		}
		seen[message] = true
		serverLog(host.ID, level, "Scan of %s: %s", host.Address, message)
	}
}

// agentOffline is how long an agent may go without asking for work before
// the log says it stopped checking in; agents ask every JobWait.
const agentOffline = 2 * time.Minute

// presence notices agents connecting and going quiet, for the log.
type presence struct {
	mu   sync.Mutex
	seen map[string]presenceEntry
}

type presenceEntry struct {
	address string
	at      time.Time
}

// checkIn records that host's agent asked for work, and logs it when the
// agent was not connected before.
func (p *presence) checkIn(host store.Host) {
	p.mu.Lock()
	_, known := p.seen[host.ID]
	p.seen[host.ID] = presenceEntry{address: host.Address, at: time.Now()}
	p.mu.Unlock()
	if !known {
		serverLog(host.ID, store.LogInfo, "The agent on %s connected", host.Address)
	}
}

// sweep logs agents that stopped checking in.
func (p *presence) sweep(now time.Time) {
	p.mu.Lock()
	var quiet []presenceEntry
	var ids []string
	for id, entry := range p.seen {
		if now.Sub(entry.at) > agentOffline {
			quiet = append(quiet, entry)
			ids = append(ids, id)
			delete(p.seen, id)
		}
	}
	p.mu.Unlock()
	for i, entry := range quiet {
		serverLog(ids[i], store.LogWarning, "The agent on %s stopped checking in; it was last seen at %s",
			entry.address, entry.at.UTC().Format("15:04:05 UTC"))
	}
}

// agentLogs stores lines from an agent's own log.
func (h *agentHub) agentLogs(w http.ResponseWriter, r *http.Request, host store.Host) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var batch agentapi.Logs
	if !readJSON(w, r, &batch) {
		return
	}
	if len(batch.Lines) > agentapi.MaxLogLines {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("send at most %d log lines at a time", agentapi.MaxLogLines))
		return
	}
	lines := make([]store.LogLine, 0, len(batch.Lines))
	for _, line := range batch.Lines {
		lines = append(lines, store.LogLine{At: line.At, Level: line.Level, Message: line.Message})
	}
	if err := store.AddLogs(store.LogAgent, host.ID, lines); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// logQuery reads the filters of GET /api/logs.
func logQuery(r *http.Request) (store.LogQuery, error) {
	values := r.URL.Query()
	query := store.LogQuery{
		Source: values.Get("source"), HostID: values.Get("host"), Level: values.Get("level"),
		Search: strings.TrimSpace(values.Get("q")),
	}
	if query.Source != "" && query.Source != store.LogServer && query.Source != store.LogAgent {
		return query, errors.New("source must be server or agent")
	}
	if query.Level != "" && !store.ValidLogLevel(query.Level) {
		return query, errors.New("level must be info, warning, or error")
	}
	if len(query.Search) > 200 {
		return query, errors.New("the search is longer than 200 characters")
	}
	if before := values.Get("before"); before != "" {
		id, err := strconv.ParseInt(before, 10, 64)
		if err != nil || id <= 0 {
			return query, errors.New("before must be a log entry ID")
		}
		query.Before = id
	}
	query.Limit, _ = strconv.Atoi(values.Get("limit"))
	query.Limit = min(max(query.Limit, 0), 1000)
	return query, nil
}

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	query, err := logQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entries, more, err := store.Logs(query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.auditLogView(r)
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "more": more})
}

// maxLogDownload bounds one download of the log.
const maxLogDownload = 50_000

// downloadLogs sends the matching entries as plain text, oldest first.
func (s *Server) downloadLogs(w http.ResponseWriter, r *http.Request) {
	query, err := logQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	query.Before, query.Limit = 0, maxLogDownload
	entries, _, err := store.Logs(query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "logs.download", "", fmt.Sprintf("%d entries", len(entries)))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="deaconguard-logs-%s.txt"`, time.Now().UTC().Format("20060102-150405")))
	w.Header().Set("Cache-Control", "no-store")
	var text strings.Builder
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		source := "server"
		if entry.Source == store.LogAgent {
			source = "agent"
		}
		if entry.Host != "" {
			source += " " + entry.Host
		} else if entry.HostID != "" {
			source += " " + entry.HostID
		}
		fmt.Fprintf(&text, "%s  %-7s  %-30s  %s\n", entry.At, strings.ToUpper(entry.Level), source, entry.Message)
	}
	w.Write([]byte(text.String()))
}

// logViewAuditInterval keeps the audit log readable: one "viewed the log"
// entry per account in this time, however often the page refreshes.
const logViewAuditInterval = 15 * time.Minute

var logViews = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

func (s *Server) auditLogView(r *http.Request) {
	actor := s.actor(r)
	logViews.Lock()
	recent := time.Since(logViews.last[actor]) < logViewAuditInterval
	if !recent {
		logViews.last[actor] = time.Now()
	}
	logViews.Unlock()
	if !recent {
		s.audit(r, "logs.view", "", "")
	}
}
