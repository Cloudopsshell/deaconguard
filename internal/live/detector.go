package live

import (
	"context"
	"errors"
	"sync"
	"time"
)

// The states live detection is in, as the dashboard shows them.
const (
	StateActive      = "active"
	StateOff         = "off"
	StateUnsupported = "unsupported"
	StateStopped     = "stopped"
	StateStarting    = "starting"
)

// Status is how live detection is doing, which the agent sends the server
// with every report.
type Status struct {
	State  string    `json:"state"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since"`
	Kernel string    `json:"kernel,omitempty"`
	// EventsLastHour counts the programs started and files written that
	// the watchers looked at in the last hour.
	EventsLastHour uint64 `json:"events_last_hour"`
	// Lost counts events the kernel dropped because the agent fell behind.
	Lost uint64 `json:"lost"`
	// Suppressed counts alerts left out over the rate limit.
	Suppressed uint64 `json:"suppressed"`
	// CPUPercent is the agent's CPU use over the last report, as a
	// percentage of one CPU, and MemoryBytes its resident memory.
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes uint64  `json:"memory_bytes"`
	// TestError says why the last "Send a test alert" couldn't run.
	TestError string `json:"test_error,omitempty"`
}

// Limits on what the agent sends.
const (
	// dedupeWindow is how long the same alert is held back after it was
	// sent; repeats are counted and sent with the next one.
	dedupeWindow = 10 * time.Minute
	// maxAlertsPerMinute bounds what a machine under a noisy attack, or a
	// misbehaving program, can send.
	maxAlertsPerMinute = 30
	// maxPending bounds the alerts waiting for the server.
	maxPending = 500
)

// Detector runs live detection for the agent.
type Detector struct {
	hostRoot string
	machine  Machine
	logf     func(format string, arguments ...any)

	mu        sync.Mutex
	status    Status
	enabled   bool
	changed   chan struct{}
	ready     chan struct{}
	pending   []Alert
	seen      map[string]*seenAlert
	minute    time.Time
	sentCount int
	minutes   [60]uint64
	minuteAt  int
	lastTotal uint64
	lastCPU   time.Duration
	lastUsage time.Time
	testAsked bool
}

type seenAlert struct {
	at      time.Time
	repeats int
}

// NewDetector prepares live detection; Run starts it.
func NewDetector(hostRoot string, logf func(format string, arguments ...any)) *Detector {
	return &Detector{
		hostRoot: hostRoot,
		machine:  newMachine(hostRoot),
		logf:     logf,
		enabled:  true,
		changed:  make(chan struct{}, 1),
		ready:    make(chan struct{}, 1),
		seen:     map[string]*seenAlert{},
		status:   Status{State: StateStarting, Since: time.Now().UTC(), Kernel: KernelRelease()},
	}
}

// Ready is signalled when alerts are waiting to be sent.
func (d *Detector) Ready() <-chan struct{} { return d.ready }

// SetEnabled turns detection on or off, as the server says.
func (d *Detector) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.enabled != enabled {
		d.enabled = enabled
		select {
		case d.changed <- struct{}{}:
		default:
		}
	}
}

// AskTest has the detector start the test program when it is active.
func (d *Detector) AskTest() {
	d.mu.Lock()
	d.testAsked = true
	d.mu.Unlock()
}

// Take returns the status and the alerts waiting to be sent, and forgets
// the alerts. Put them back with Return if sending fails.
func (d *Detector) Take() (Status, []Alert) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshUsage()
	alerts := d.pending
	d.pending = nil
	status := d.status
	status.EventsLastHour = 0
	for _, count := range d.minutes {
		status.EventsLastHour += count
	}
	return status, alerts
}

// Return puts back alerts that couldn't be sent.
func (d *Detector) Return(alerts []Alert) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending = append(alerts, d.pending...)
	if len(d.pending) > maxPending {
		d.status.Suppressed += uint64(len(d.pending) - maxPending)
		d.pending = d.pending[len(d.pending)-maxPending:]
	}
}

func (d *Detector) refreshUsage() {
	cpu, memory := selfUsage()
	now := time.Now()
	if !d.lastUsage.IsZero() {
		if elapsed := now.Sub(d.lastUsage); elapsed > 0 {
			d.status.CPUPercent = float64(cpu-d.lastCPU) / float64(elapsed) * 100
		}
	}
	d.lastCPU, d.lastUsage = cpu, now
	d.status.MemoryBytes = memory
}

func (d *Detector) setState(state, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status.State != state || d.status.Reason != reason {
		d.status.State, d.status.Reason, d.status.Since = state, reason, time.Now().UTC()
	}
	select {
	case d.ready <- struct{}{}:
	default:
	}
}

// add queues alerts, holding back repeats and anything over the rate limit.
func (d *Detector) add(alerts []Alert, now time.Time) {
	if len(alerts) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.minute) >= time.Minute {
		d.minute, d.sentCount = now, 0
	}
	queued := false
	for _, alert := range alerts {
		key := alert.Rule + "\x00" + alert.Program + "\x00" + alert.Parent + "\x00" + alert.Path
		if !alert.Test {
			if seen, ok := d.seen[key]; ok && now.Sub(seen.at) < dedupeWindow {
				seen.repeats++
				continue
			} else if ok {
				alert.Repeats = seen.repeats
			}
			if d.sentCount >= maxAlertsPerMinute {
				d.status.Suppressed++
				continue
			}
			d.sentCount++
			d.seen[key] = &seenAlert{at: now}
		}
		d.pending = append(d.pending, alert)
		queued = true
	}
	for key, seen := range d.seen {
		if now.Sub(seen.at) >= 2*dedupeWindow {
			delete(d.seen, key)
		}
	}
	if len(d.pending) > maxPending {
		d.status.Suppressed += uint64(len(d.pending) - maxPending)
		d.pending = d.pending[len(d.pending)-maxPending:]
	}
	if queued {
		select {
		case d.ready <- struct{}{}:
		default:
		}
	}
}

// count records the watchers' running total of events looked at, a minute
// at a time, for the last hour's count.
func (d *Detector) count(total uint64, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if total < d.lastTotal {
		d.lastTotal = 0
	}
	minute := int(now.Unix()/60) % len(d.minutes)
	if minute != d.minuteAt {
		d.minuteAt = minute
		d.minutes[minute] = 0
	}
	d.minutes[minute] += total - d.lastTotal
	d.lastTotal = total
}

// Run keeps live detection going until ctx ends: on while the server says
// so, restarted if it stops, and off otherwise.
func (d *Detector) Run(ctx context.Context) {
	for ctx.Err() == nil {
		d.mu.Lock()
		enabled := d.enabled
		d.mu.Unlock()
		if !enabled {
			d.setState(StateOff, "turned off on the dashboard")
			select {
			case <-ctx.Done():
				return
			case <-d.changed:
			}
			continue
		}
		w, err := startWatcher(d.hostRoot)
		var unsupported ErrUnsupported
		switch {
		case errors.As(err, &unsupported):
			d.setState(StateUnsupported, unsupported.Reason)
			d.logf("Live detection can't run on this machine: %s", unsupported.Reason)
			if !d.wait(ctx, time.Hour) {
				return
			}
			continue
		case err != nil:
			d.setState(StateStopped, "couldn't start: "+err.Error())
			d.logf("Live detection couldn't start, retrying in a minute: %v", err)
			if !d.wait(ctx, time.Minute) {
				return
			}
			continue
		}
		d.mu.Lock()
		d.lastTotal = 0
		d.mu.Unlock()
		d.setState(StateActive, "")
		d.logf("Live detection is active")
		err = d.watch(ctx, w)
		w.close()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			d.setState(StateStopped, err.Error())
			d.logf("Live detection stopped, restarting in a minute: %v", err)
			if !d.wait(ctx, time.Minute) {
				return
			}
		}
	}
}

// wait waits for delay, or less if the server turns detection off or on.
func (d *Detector) wait(ctx context.Context, delay time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-d.changed:
		return true
	case <-time.After(delay):
		return true
	}
}

// watch reads events until ctx ends, detection is turned off, or the
// watchers fail.
func (d *Detector) watch(ctx context.Context, w eventSource) error {
	lastCount := time.Time{}
	for ctx.Err() == nil {
		select {
		case <-d.changed:
			d.mu.Lock()
			enabled := d.enabled
			d.mu.Unlock()
			if !enabled {
				return nil
			}
		default:
		}
		if err := w.poll(1000, func(event Event) {
			d.add(Evaluate(event, d.machine), time.Now())
		}); err != nil {
			return err
		}
		now := time.Now()
		if now.Sub(lastCount) >= 5*time.Second {
			lastCount = now
			counters, err := w.counters()
			if err != nil {
				return err
			}
			d.count(counters.Execs+counters.Writes, now)
			d.mu.Lock()
			d.status.Lost = counters.Lost
			d.mu.Unlock()
		}
		d.mu.Lock()
		test := d.testAsked
		d.testAsked = false
		d.mu.Unlock()
		if test {
			err := runTestProgram(d.hostRoot)
			d.mu.Lock()
			d.status.TestError = ""
			if err != nil {
				d.status.TestError = err.Error()
			}
			d.mu.Unlock()
			if err != nil {
				d.logf("Couldn't send a test alert: %v", err)
			}
		}
	}
	return nil
}

// eventSource is the watchers as watch uses them.
type eventSource interface {
	poll(timeoutMS int, handle func(Event)) error
	counters() (Counters, error)
}
