package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"opsarmor/internal/scan"
	"opsarmor/internal/store"
)

const (
	// maxEvents bounds one scan's live log; the oldest lines are dropped.
	maxEvents = 2000
	// keepLogs is how long a finished scan's live log stays in memory and in
	// the activity list, so its console can be reopened.
	keepLogs = 30 * time.Minute
)

// eventLog is the in-memory live log of one scan. It is not persisted; the
// scan's results are stored as usual when it finishes.
type eventLog struct {
	mu       sync.Mutex
	events   []scan.Event
	next     int
	changed  chan struct{}
	finished time.Time
	activity Activity
}

// Activity describes a running or recently finished scan.
type Activity struct {
	ScanID     string   `json:"scan_id"`
	HostID     string   `json:"host_id"`
	Address    string   `json:"address"`
	Username   string   `json:"username"`
	Port       int      `json:"port"`
	Checks     []string `json:"checks"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Status     string   `json:"status"`
}

func newEventLog(host store.Host, record store.Scan, checks []string) *eventLog {
	return &eventLog{changed: make(chan struct{}), activity: Activity{
		ScanID: record.ID, HostID: host.ID, Address: host.Address, Username: host.Username, Port: host.Port,
		Checks: checks, StartedAt: record.StartedAt, Status: record.Status,
	}}
}

func (l *eventLog) add(event scan.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	event.Seq = l.next
	event.Time = time.Now().UTC()
	l.events = append(l.events, event)
	if len(l.events) > maxEvents {
		l.events = l.events[len(l.events)-maxEvents:]
	}
	close(l.changed)
	l.changed = make(chan struct{})
}

// snapshot returns every event in the log.
func (l *eventLog) snapshot() []scan.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]scan.Event(nil), l.events...)
}

func (l *eventLog) finish(status string) {
	l.mu.Lock()
	l.finished = time.Now().UTC()
	l.activity.Status = status
	l.activity.FinishedAt = l.finished.Format(time.RFC3339)
	l.mu.Unlock()
}

// since returns events after seq, whether the scan has finished, and a
// channel that closes when more events arrive.
func (l *eventLog) since(seq int) ([]scan.Event, bool, <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	events := make([]scan.Event, 0)
	for _, event := range l.events {
		if event.Seq > seq {
			events = append(events, event)
		}
	}
	return events, !l.finished.IsZero(), l.changed
}

func (r *runner) logFor(scanID string) *eventLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logs[scanID]
}

// pruneLogs drops live logs of scans that finished long ago. r.mu must be held.
func (r *runner) pruneLogs() {
	for id, log := range r.logs {
		log.mu.Lock()
		expired := !log.finished.IsZero() && time.Since(log.finished) > keepLogs
		log.mu.Unlock()
		if expired {
			delete(r.logs, id)
		}
	}
}

func (r *runner) activity() []Activity {
	r.mu.Lock()
	logs := make([]*eventLog, 0, len(r.logs))
	for _, log := range r.logs {
		logs = append(logs, log)
	}
	r.mu.Unlock()
	result := make([]Activity, 0)
	for _, log := range logs {
		log.mu.Lock()
		item, finished := log.activity, log.finished
		log.mu.Unlock()
		if !finished.IsZero() && time.Since(finished) > keepLogs {
			continue
		}
		if finished.IsZero() {
			// A running scan may be paused waiting for the user.
			if record, err := store.GetScan(item.ScanID); err == nil {
				item.Status = record.Status
			}
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StartedAt > result[j].StartedAt })
	return result
}

func (s *Server) listActivity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.runner.activity())
}

type eventsResponse struct {
	Events   []scan.Event `json:"events"`
	Finished bool         `json:"finished"`
}

// scanEvents returns a scan's log lines after ?after=SEQ, and whether the
// scan has finished. The UI polls it; short requests never tie up the
// browser's small pool of connections to this server the way a stream would.
func (s *Server) scanEvents(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	if log := s.runner.logFor(r.PathValue("id")); log != nil {
		events, finished, _ := log.since(after)
		writeJSON(w, http.StatusOK, eventsResponse{Events: events, Finished: finished})
		return
	}
	// Not running in this process: return the log saved with the scan.
	saved, err := store.ScanEvents(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var events []scan.Event
	if saved == nil || json.Unmarshal(saved, &events) != nil {
		writeError(w, http.StatusNotFound, errors.New("no activity log was saved for this scan"))
		return
	}
	result := make([]scan.Event, 0, len(events))
	for _, event := range events {
		if event.Seq > after {
			result = append(result, event)
		}
	}
	writeJSON(w, http.StatusOK, eventsResponse{Events: result, Finished: true})
}
