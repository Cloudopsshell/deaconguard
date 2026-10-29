package server

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

func warnings(t *testing.T) []string {
	t.Helper()
	entries, _, err := store.Logs(store.LogQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var messages []string
	for _, entry := range entries {
		if entry.Level == store.LogWarning {
			messages = append(messages, entry.Message)
		}
	}
	return messages
}

func TestSlowRequestsAreLogged(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	d := newDiagnostics()
	clock := time.Date(2026, 10, 29, 20, 0, 0, 0, time.UTC)
	var cpu time.Duration
	d.now = func() time.Time { return clock }
	d.cpu = func() time.Duration { return cpu }
	took := time.Duration(0)
	handler := d.timed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clock = clock.Add(took)
		cpu += took
		w.WriteHeader(http.StatusTeapot)
	}))
	call := func(path string) {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path+"?secret=x", nil))
	}

	took = 300 * time.Millisecond
	call("/api/summary")
	if len(warnings(t)) != 0 {
		t.Fatalf("a fast request was logged: %v", warnings(t))
	}
	took = 12 * time.Second
	call("/api/summary")
	logged := warnings(t)
	if len(logged) != 1 || logged[0] != "Slow request: GET /api/summary took 12s (status 418); the server used 12s of CPU meanwhile" {
		t.Fatalf("logged %q", logged)
	}
	// Once every few minutes per path; the query string is never logged.
	call("/api/summary")
	if len(warnings(t)) != 1 || strings.Contains(strings.Join(warnings(t), ""), "secret") {
		t.Fatalf("logged %q", warnings(t))
	}
	clock = clock.Add(slowRequestQuiet)
	call("/api/summary")
	if len(warnings(t)) != 2 {
		t.Fatalf("after the quiet period: %q", warnings(t))
	}
	// An agent waiting for its next job isn't slow.
	call(agentapi.PathPrefix + "job")
	if len(warnings(t)) != 2 {
		t.Fatalf("the agent's long poll was logged: %q", warnings(t))
	}
}

// spin keeps a CPU busy until stop is set, as the work the watchdog should
// name.
func spin(stop *atomic.Bool) int {
	n := 0
	for !stop.Load() {
		for i := range 1000 {
			n += i % 7
		}
	}
	return n
}

func TestBusyInNamesTheWork(t *testing.T) {
	var stop atomic.Bool
	go spin(&stop)
	defer stop.Store(true)
	where := busyIn(context.Background(), 20, 5*time.Millisecond)
	if !strings.Contains(where, "server.spin") {
		t.Fatalf("busy in %q", where)
	}
	if strings.Contains(where, "busyIn") {
		t.Fatalf("the sampler named itself: %q", where)
	}
}

func TestRunningFunctions(t *testing.T) {
	dump := []byte(`goroutine 1 [running]:
deaconguard/internal/server.busyIn(...)
	/src/diagnostics.go:10 +0x1
goroutine 7 [runnable]:
modernc.org/sqlite/lib.sqlite3VdbeExec(0x1)
	/go/vdbe.go:1 +0x1
deaconguard/internal/store.queryLatestFindings({0x0, 0x0})
	/src/scans.go:761 +0x1
deaconguard/internal/store.Vulnerabilities()
	/src/scans.go:786 +0x1
deaconguard/internal/server.buildSummary()
	/src/server.go:497 +0x1
goroutine 9 [select]:
deaconguard/internal/server.(*Server).startImageScanner.func1()
	/src/images.go:120 +0x1
goroutine 11 [running]:
runtime.gcBgMarkWorker(0x1)
	/go/mgc.go:1 +0x1
`)
	got := runningFunctions(dump)
	if len(got) != 1 || got[0] != "store.queryLatestFindings ← store.Vulnerabilities" {
		t.Fatalf("got %q", got)
	}
}

func TestWatchdogLogsHighCPU(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	d := newDiagnostics()
	d.tick, d.window = 20*time.Millisecond, 100*time.Millisecond
	start := time.Now()
	// Three cores' worth of CPU time.
	d.cpu = func() time.Duration { return 3 * time.Since(start) }
	request := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	d.inFlight[request] = time.Now().Add(-40 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.watch(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(warnings(t)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	logged := warnings(t)
	if len(logged) != 1 || !strings.HasPrefix(logged[0], "High CPU: the server used 3.0 cores") || !strings.Contains(logged[0], "Requests in progress: GET /api/summary (40s)") {
		t.Fatalf("logged %q", logged)
	}
}

func TestCPUProfileDownload(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	if bad := do(t, s, call{method: http.MethodGet, path: "/api/diagnostics/cpu?seconds=1", cookie: cookie}); bad.Code != http.StatusBadRequest {
		t.Fatalf("1 second: %d", bad.Code)
	}
	answer := do(t, s, call{method: http.MethodGet, path: "/api/diagnostics/cpu?seconds=5", cookie: cookie})
	if answer.Code != http.StatusOK || answer.Body.Len() == 0 || !strings.Contains(answer.Header().Get("Content-Disposition"), ".pprof") {
		t.Fatalf("profile: %d, %d bytes, %q", answer.Code, answer.Body.Len(), answer.Header().Get("Content-Disposition"))
	}
}

func TestAccessLog(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	var output strings.Builder
	log.SetOutput(&output)
	defer log.SetOutput(os.Stderr)
	d := newDiagnostics()
	status := http.StatusOK
	handler := d.timed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noteUser(r, "admin")
		w.WriteHeader(status)
	}))
	call := func(path string) {
		request := httptest.NewRequest(http.MethodGet, path+"?token=secret", nil)
		request.RemoteAddr = "192.0.2.7:51000"
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	call("/api/summary")
	if output.Len() != 0 {
		t.Fatalf("logged with the access log off: %q", output.String())
	}
	d.accessLog = true
	call("/api/summary")
	call("/api/prompts")
	status = http.StatusInternalServerError
	call("/api/prompts")
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "ACCESS GET /api/summary 200 0s user=admin ip=192.0.2.7") || !strings.Contains(lines[1], "ACCESS GET /api/prompts 500") {
		t.Fatalf("access log: %q", lines)
	}
	if strings.Contains(output.String(), "secret") {
		t.Fatalf("the query string was logged: %q", output.String())
	}
}

func TestServerLogLevelOnStdout(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	var output strings.Builder
	log.SetOutput(&output)
	defer log.SetOutput(os.Stderr)
	serverLog("", store.LogWarning, "Could not check %s", "x")
	if !strings.HasSuffix(strings.TrimSpace(output.String()), "WARNING Could not check x") {
		t.Fatalf("stdout: %q", output.String())
	}
}
