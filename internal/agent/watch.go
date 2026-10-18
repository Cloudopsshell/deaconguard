package agent

import (
	"strings"
	"sync"
	"time"

	"deaconguard/internal/target"
)

// containerIDsCommand lists the IDs of the running containers, cheaply: the
// watcher runs it about once a minute.
const containerIDsCommand = `{ command -v docker >/dev/null 2>&1 && docker ps -q --no-trunc; ` +
	`command -v podman >/dev/null 2>&1 && podman ps -q --no-trunc; ` +
	`command -v crictl >/dev/null 2>&1 && crictl ps -q; } 2>/dev/null | head -n 2000; true`

const watchInterval = time.Minute

// containerWatch notices containers that start between scans. The server
// decides whether to scan them (a host setting); the agent only counts them.
type containerWatch struct {
	mu      sync.Mutex
	known   map[string]bool
	fresh   int
	checked time.Time
	run     func(command string) ([]byte, error)
}

func newContainerWatch(machine target.Target) *containerWatch {
	return &containerWatch{run: func(command string) ([]byte, error) {
		return machine.Run(command, nil, 1<<20, 30*time.Second)
	}}
}

// poll looks at the running containers at most once per watchInterval and
// counts the ones not seen before. The first look only learns what runs.
func (w *containerWatch) poll(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.checked) < watchInterval {
		return
	}
	w.checked = now
	output, err := w.run(containerIDsCommand)
	if err != nil {
		return
	}
	current := make(map[string]bool)
	for _, id := range strings.Fields(string(output)) {
		current[id] = true
	}
	if w.known != nil {
		for id := range current {
			if !w.known[id] {
				w.fresh++
			}
		}
	}
	w.known = current
}

// take returns the count of new containers to tell the server, and resets it.
func (w *containerWatch) take() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	fresh := w.fresh
	w.fresh = 0
	return fresh
}

// giveBack keeps a count the server didn't receive, for the next request.
func (w *containerWatch) giveBack(fresh int) {
	w.mu.Lock()
	w.fresh += fresh
	w.mu.Unlock()
}
