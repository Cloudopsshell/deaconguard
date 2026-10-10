package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"deaconguard/internal/agentapi"
)

// maxPendingLogLines bounds what the agent keeps while the server cannot be
// reached; the oldest lines go first.
const maxPendingLogLines = 2000

// agentLog writes the agent's log to the service journal and keeps each line
// until the server has it, for the host's page on the dashboard.
type agentLog struct {
	journal func(format string, arguments ...any)
	mu      sync.Mutex
	pending []agentapi.LogLine
	dropped int
}

func (l *agentLog) info(format string, arguments ...any) { l.add("info", format, arguments...) }
func (l *agentLog) warn(format string, arguments ...any) { l.add("warning", format, arguments...) }
func (l *agentLog) fail(format string, arguments ...any) { l.add("error", format, arguments...) }

func (l *agentLog) add(level, format string, arguments ...any) {
	l.journal(format, arguments...)
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pending) == maxPendingLogLines {
		l.pending = l.pending[1:]
		l.dropped++
	}
	l.pending = append(l.pending, agentapi.LogLine{At: time.Now().UTC(), Level: level, Message: fmt.Sprintf(format, arguments...)})
}

// send delivers the pending lines. Lines the server could not take because
// the connection failed are kept for the next try; lines it refuses, such as
// a server older than 0.6.0 that has no log, are dropped, since the journal
// has them.
func (l *agentLog) send(ctx context.Context, client *client) {
	for ctx.Err() == nil {
		l.mu.Lock()
		batch := l.pending[:min(len(l.pending), agentapi.MaxLogLines)]
		dropped := l.dropped
		l.mu.Unlock()
		if len(batch) == 0 {
			return
		}
		lines := batch
		if dropped > 0 {
			note := agentapi.LogLine{At: batch[0].At, Level: "warning",
				Message: fmt.Sprintf("%d earlier log lines were dropped while the server could not be reached; the service journal has them", dropped)}
			lines = append([]agentapi.LogLine{note}, batch...)
		}
		err := client.call(ctx, http.MethodPost, agentapi.PathLogs, agentapi.Logs{Lines: lines}, nil, 30*time.Second)
		if err != nil && !errors.Is(err, errRejected) {
			return
		}
		l.mu.Lock()
		// Lines dropped from the front while sending were part of this batch:
		// the server has them, so they are neither pending nor dropped.
		during := l.dropped - dropped
		l.pending = l.pending[max(len(batch)-during, 0):]
		l.dropped = max(during-len(batch), 0)
		l.mu.Unlock()
		if err != nil {
			return
		}
	}
}
