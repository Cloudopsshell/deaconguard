package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

// Diagnostics for a busy server: requests that take long are logged with
// the CPU the server used meanwhile, a watchdog logs where the time goes when
// the server keeps more than a core busy, and admins can download a CPU
// profile.

const (
	// slowRequest is how long a request may take before it is logged.
	slowRequest = 2 * time.Second
	// slowRequestQuiet is how often one method and path is logged as slow.
	slowRequestQuiet = 5 * time.Minute
	// busyCores is the CPU, in cores, that the watchdog counts as busy when
	// it lasts busyFor.
	busyCores = 1.0
	busyFor   = 30 * time.Second
	// busyQuiet is how often the watchdog logs.
	busyQuiet = 10 * time.Minute
	// cpuTick is how often the watchdog measures.
	cpuTick = 5 * time.Second
)

// processCPU is the CPU time the server process has used, user and system.
func processCPU() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// diagnostics tracks requests in progress and when each kind was last
// logged.
type diagnostics struct {
	mu       sync.Mutex
	inFlight map[*http.Request]time.Time
	logged   map[string]time.Time
	busyAt   time.Time
	// accessLog writes a line to standard output for each request, when the
	// server runs with --access-log.
	accessLog bool
	// now and cpu are the clock and the CPU meter, and tick and window how
	// often and over how long the watchdog measures; tests change them.
	now          func() time.Time
	cpu          func() time.Duration
	tick, window time.Duration
}

func newDiagnostics() *diagnostics {
	return &diagnostics{inFlight: map[*http.Request]time.Time{}, logged: map[string]time.Time{}, now: time.Now, cpu: processCPU, tick: cpuTick, window: busyFor}
}

// waits reports the requests that wait on purpose, such as an agent asking
// for its next job, which aren't slow.
func waits(r *http.Request) bool {
	return r.URL.Path == agentapi.PathPrefix+"job" || strings.HasPrefix(r.URL.Path, "/api/diagnostics/")
}

// heartbeat reports the polls the access log leaves out, as they come every
// few seconds while nothing happens: an agent asking for its next job, an
// open dashboard asking for sudo prompts, and Kubernetes checking that the
// server is up. They are logged when they fail.
func heartbeat(r *http.Request, status int) bool {
	return status < 400 && (r.URL.Path == agentapi.PathPrefix+"job" || r.URL.Path == "/api/prompts" ||
		strings.HasPrefix(r.UserAgent(), "kube-probe/"))
}

// requestInfo is what the handlers learn about a request that the access
// log needs: who made it.
type requestInfo struct{ user string }

type requestInfoKey struct{}

// noteUser records who made a request, for the access log.
func noteUser(r *http.Request, name string) {
	if info, ok := r.Context().Value(requestInfoKey{}).(*requestInfo); ok {
		info.user = name
	}
}

// LogRequests turns the access log on: a line on standard output for each
// request. Call it before serving.
func (s *Server) LogRequests(on bool) { s.diagnostics.accessLog = on }

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *statusRecorder) Write(data []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	return recorder.ResponseWriter.Write(data)
}

func (recorder *statusRecorder) Unwrap() http.ResponseWriter { return recorder.ResponseWriter }

// timed logs a request that takes longer than slowRequest, with the CPU the
// whole server used meanwhile, at most once every slowRequestQuiet for each
// method and path.
func (d *diagnostics) timed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, cpu := d.now(), d.cpu()
		info := &requestInfo{}
		r = r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, info))
		waiting := waits(r)
		if !waiting {
			d.mu.Lock()
			d.inFlight[r] = start
			d.mu.Unlock()
		}
		recorder := &statusRecorder{ResponseWriter: w}
		defer func() {
			took, used := d.now().Sub(start), d.cpu()-cpu
			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			key := r.Method + " " + r.URL.Path
			if d.accessLog && !heartbeat(r, status) {
				user := info.user
				if user == "" {
					user = "-"
				}
				log.Printf("ACCESS %s %d %s user=%s ip=%s", key, status, took.Round(time.Millisecond), user, remoteIP(r))
			}
			if waiting {
				return
			}
			d.mu.Lock()
			delete(d.inFlight, r)
			quiet := d.now().Sub(d.logged[key]) < slowRequestQuiet
			if took >= slowRequest && !quiet {
				d.logged[key] = d.now()
			}
			d.mu.Unlock()
			if took >= slowRequest && !quiet {
				serverLog("", store.LogWarning, "Slow request: %s took %s (status %d); the server used %s of CPU meanwhile",
					key, took.Round(100*time.Millisecond), status, used.Round(100*time.Millisecond))
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

// inProgress describes the requests running now, longest first.
func (d *diagnostics) inProgress() string {
	d.mu.Lock()
	type running struct {
		what string
		for_ time.Duration
	}
	var list []running
	for r, start := range d.inFlight {
		list = append(list, running{r.Method + " " + r.URL.Path, d.now().Sub(start)})
	}
	d.mu.Unlock()
	if len(list) == 0 {
		return "none"
	}
	sort.Slice(list, func(i, j int) bool { return list[i].for_ > list[j].for_ })
	var parts []string
	for index, item := range list {
		if index == 5 {
			parts = append(parts, fmt.Sprintf("and %d more", len(list)-5))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", item.what, item.for_.Round(time.Second)))
	}
	return strings.Join(parts, ", ")
}

// watch measures the server's CPU every cpuTick, and when it has kept more
// than busyCores busy for busyFor, logs what its code is doing.
func (d *diagnostics) watch(ctx context.Context) {
	ticker := time.NewTicker(d.tick)
	defer ticker.Stop()
	type sample struct {
		at  time.Time
		cpu time.Duration
	}
	var samples []sample
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		samples = append(samples, sample{d.now(), d.cpu()})
		// Keep a window of d.window.
		for len(samples) > 1 && d.now().Sub(samples[1].at) >= d.window {
			samples = samples[1:]
		}
		first, last := samples[0], samples[len(samples)-1]
		span := last.at.Sub(first.at)
		if span < d.window {
			continue
		}
		cores := float64(last.cpu-first.cpu) / float64(span)
		if cores < busyCores || d.now().Sub(d.busyAt) < busyQuiet {
			continue
		}
		d.busyAt = d.now()
		requests := d.inProgress()
		where := busyIn(ctx, 50, d.tick/50)
		serverLog("", store.LogWarning, "High CPU: the server used %.1f cores for the last %s. Busy in: %s. Requests in progress: %s",
			cores, span.Round(time.Second), where, requests)
	}
}

// busyIn samples every goroutine's stack count times, every interval, and
// says which DeaconGuard functions the running ones were in, most first.
func busyIn(ctx context.Context, count int, interval time.Duration) string {
	seen := map[string]int{}
	total := 0
	buffer := make([]byte, 1<<20)
	for range count {
		n := runtime.Stack(buffer, true)
		for _, function := range runningFunctions(buffer[:n]) {
			seen[function]++
			total++
		}
		select {
		case <-ctx.Done():
			return "unknown (stopped)"
		case <-time.After(interval):
		}
	}
	if total == 0 {
		return "nothing of DeaconGuard's own (the Go runtime, such as garbage collection, or system calls)"
	}
	type entry struct {
		function string
		count    int
	}
	var list []entry
	for function, count := range seen {
		list = append(list, entry{function, count})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].count > list[j].count || list[i].count == list[j].count && list[i].function < list[j].function
	})
	var parts []string
	for index, item := range list {
		if index == 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d%%", item.function, item.count*100/total))
	}
	return strings.Join(parts, ", ")
}

// runningFunctions reads a goroutine dump and returns, for each goroutine
// that was running or runnable, where in DeaconGuard's code it was: the
// innermost DeaconGuard function on its stack and the DeaconGuard function
// that called it, such as "store.Vulnerabilities ← server.buildSummary".
// The goroutine taking the sample is left out.
func runningFunctions(dump []byte) []string {
	var found []string
	var frames []string
	active, sampler := false, false
	flush := func() {
		if active && !sampler && len(frames) > 0 {
			found = append(found, strings.Join(frames, " ← "))
		}
		frames = nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(dump))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "goroutine ") {
			flush()
			active = strings.Contains(line, "[running") || strings.Contains(line, "[runnable")
			sampler = false
			continue
		}
		if !active || strings.HasPrefix(line, "\t") || line == "" || len(frames) == 2 {
			continue
		}
		function := line
		if index := strings.LastIndex(function, "("); index > 0 {
			function = function[:index]
		}
		if !strings.HasPrefix(function, "deaconguard/") {
			continue
		}
		if strings.Contains(function, "server.busyIn") {
			sampler = true
		}
		frames = append(frames, strings.TrimPrefix(function, "deaconguard/internal/"))
	}
	flush()
	return found
}

// cpuProfile serves a CPU profile of the server over the next seconds (5 to
// 60, 30 by default), for admins, to open with go tool pprof.
func (s *Server) cpuProfile(w http.ResponseWriter, r *http.Request) {
	seconds := 30
	if text := r.URL.Query().Get("seconds"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 5 || value > 60 {
			writeError(w, http.StatusBadRequest, errors.New("seconds must be from 5 to 60"))
			return
		}
		seconds = value
	}
	var profile bytes.Buffer
	if err := pprof.StartCPUProfile(&profile); err != nil {
		writeError(w, http.StatusConflict, fmt.Errorf("a CPU profile is already being taken: %w", err))
		return
	}
	select {
	case <-r.Context().Done():
	case <-time.After(time.Duration(seconds) * time.Second):
	}
	pprof.StopCPUProfile()
	s.audit(r, "diagnostics.cpu_profile", fmt.Sprintf("%ds", seconds), "")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="deaconguard-cpu-%s.pprof"`, time.Now().UTC().Format("20060102-150405")))
	w.Write(profile.Bytes())
}
