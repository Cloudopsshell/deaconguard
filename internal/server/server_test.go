package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

func newTestServer(t *testing.T, scan scanFunc) *Server {
	t.Helper()
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	ui := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>DeaconGuard</title>")},
		"assets/app.js": {Data: []byte("console.log('ui')")},
	}
	s, err := New(ui, scan)
	if err != nil {
		t.Fatal(err)
	}
	s.localAvailable = func() error { return nil }
	return s
}

func request(t *testing.T, s *Server, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1:7480"+target, reader)
	if method == http.MethodPost || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, req)
	return recorder
}

func decode[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	return value
}

func TestScanFlowStoresReportAndAggregates(t *testing.T) {
	s := newTestServer(t, func(host store.Host, _ []string, _ scan.Options) (map[string]any, error) {
		return map[string]any{
			"host_id": host.ID, "address": host.Address, "os": "Ubuntu 24.04 LTS",
			"findings": []any{map[string]any{
				"id": "CVE-2026-1000", "package": "openssl", "installed_version": "3.0.1",
				"fixed_version": "3.0.2", "severity": "CRITICAL",
			}},
		}, nil
	})
	created := request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"})
	if created.Code != http.StatusCreated {
		t.Fatalf("add host: %d %s", created.Code, created.Body.String())
	}
	host := decode[store.Host](t, created)
	if host.Transport != store.TransportLocal {
		t.Fatalf("host transport = %q", host.Transport)
	}
	response := request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{})
	if response.Code != http.StatusAccepted {
		t.Fatalf("start scan: %d %s", response.Code, response.Body.String())
	}
	started := decode[store.Scan](t, response)
	s.runner.wait()

	detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil))
	if detail.Scan.Status != store.ScanSucceeded || detail.Report["os"] != "Ubuntu 24.04 LTS" {
		t.Fatalf("scan detail = %+v", detail)
	}
	summary := decode[summary](t, request(t, s, http.MethodGet, "/api/summary", nil))
	if summary.Hosts != 1 || summary.ScannedHosts != 1 || summary.Severity.Critical != 1 || summary.UniqueCVEs != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	affected := decode[[]store.AffectedPackage](t, request(t, s, http.MethodGet, "/api/vulnerabilities/CVE-2026-1000", nil))
	if len(affected) != 1 || affected[0].Package != "openssl" {
		t.Fatalf("affected = %+v", affected)
	}
}

func TestFailedScanIsNeverReportedClean(t *testing.T) {
	s := newTestServer(t, func(store.Host, []string, scan.Options) (map[string]any, error) {
		return nil, errors.New("advisory feed unavailable")
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{}))
	s.runner.wait()
	detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil))
	if detail.Scan.Status != store.ScanFailed || detail.Report != nil || !strings.Contains(detail.Scan.Error, "advisory feed") {
		t.Fatalf("failed scan detail = %+v", detail)
	}
	summary := decode[summary](t, request(t, s, http.MethodGet, "/api/summary", nil))
	if summary.ScannedHosts != 0 || summary.AttentionHosts != 1 {
		t.Fatalf("a failed scan must count as needing attention, not scanned: %+v", summary)
	}
}

// waitForPrompt polls the prompt list the way the browser does.
func waitForPrompt(t *testing.T, s *Server, kind string) Prompt {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, prompt := range decode[[]Prompt](t, request(t, s, http.MethodGet, "/api/prompts", nil)) {
			if prompt.Kind == kind {
				return prompt
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s prompt appeared", kind)
	return Prompt{}
}

func TestCancellingAPromptFailsTheScan(t *testing.T) {
	s := newTestServer(t, func(host store.Host, _ []string, options scan.Options) (map[string]any, error) {
		_, err := options.SudoPassword(nil)
		return nil, err
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{}))
	waitForPrompt(t, s, PromptSudo)
	if response := request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{}); response.Code != http.StatusConflict {
		t.Fatalf("a second scan started while the first waits for input: %d", response.Code)
	}
	request(t, s, http.MethodPost, "/api/scans/"+started.ID+"/respond", map[string]any{"cancel": true})
	s.runner.wait()
	detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil))
	if detail.Scan.Status != store.ScanFailed || !strings.Contains(detail.Scan.Error, "sudo password was not provided") {
		t.Fatalf("cancelled scan = %+v", detail.Scan)
	}
	if response := request(t, s, http.MethodPost, "/api/scans/"+started.ID+"/respond", map[string]any{"value": "late"}); response.Code != http.StatusNotFound {
		t.Fatalf("answering a finished scan should 404, got %d", response.Code)
	}
}

func TestClosingServerStopsWaitingScans(t *testing.T) {
	s := newTestServer(t, func(host store.Host, _ []string, options scan.Options) (map[string]any, error) {
		_, err := options.SudoPassword(nil)
		return nil, err
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{}))
	waitForPrompt(t, s, PromptSudo)
	s.Close()
	if detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil)); detail.Scan.Status != store.ScanFailed {
		t.Fatalf("scan after shutdown = %+v", detail.Scan)
	}
}

func TestLocalOnlyProtections(t *testing.T) {
	s := newTestServer(t, nil)
	cases := []struct {
		name    string
		mutate  func(*http.Request)
		wantErr int
	}{
		{"DNS rebinding host", func(r *http.Request) { r.Host = "attacker.example:7480" }, http.StatusForbidden},
		{"cross-origin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, http.StatusForbidden},
		{"cross-site fetch", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"form post", func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7480/api/hosts",
				strings.NewReader(`{"address":"x.example","username":"scanner"}`))
			req.Header.Set("Content-Type", "application/json")
			tc.mutate(req)
			recorder := httptest.NewRecorder()
			s.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantErr {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.wantErr, recorder.Body.String())
			}
		})
	}
	if hosts, err := store.ListHosts(); err != nil || len(hosts) != 0 {
		t.Fatalf("a rejected request changed data: %+v, %v", hosts, err)
	}
}

func TestServesUIWithClientRouteFallback(t *testing.T) {
	s := newTestServer(t, nil)
	page := request(t, s, http.MethodGet, "/hosts/some-id", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "<title>DeaconGuard</title>") {
		t.Fatalf("client route: %d %s", page.Code, page.Body.String())
	}
	asset := request(t, s, http.MethodGet, "/assets/app.js", nil)
	if asset.Code != http.StatusOK || !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", asset.Code, asset.Header())
	}
	if missing := request(t, s, http.MethodGet, "/api/nope", nil); missing.Code != http.StatusNotFound {
		t.Fatalf("unknown API path should 404, got %d", missing.Code)
	}
}

func TestIsLoopback(t *testing.T) {
	for address, want := range map[string]bool{
		"127.0.0.1:7480": true, "localhost:80": true, "[::1]:7480": true,
		"0.0.0.0:7480": false, "192.168.1.5:7480": false, "7480": false,
	} {
		if got := IsLoopback(address); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", address, got, want)
		}
	}
}

func TestChosenChecksAndSudoPrompt(t *testing.T) {
	var gotChecks []string
	var sudoPassword string
	s := newTestServer(t, func(host store.Host, selected []string, options scan.Options) (map[string]any, error) {
		gotChecks = selected
		password, err := options.SudoPassword(nil)
		if err != nil {
			return nil, err
		}
		sudoPassword = string(password)
		return map[string]any{
			"host_id": host.ID, "checks_run": selected,
			"check_results": map[string]any{checks.Malware: map[string]any{
				"status": "completed", "privileged": true,
				"findings": []any{map[string]any{"rule": "malware.crypto-miner", "severity": "CRITICAL", "title": "miner"}},
			}},
		}, nil
	})
	checkList := decode[[]checks.Definition](t, request(t, s, http.MethodGet, "/api/checks", nil))
	if len(checkList) != 6 || checkList[0].ID != checks.Packages || !checkList[0].Default || checkList[5].ID != checks.YARA {
		t.Fatalf("checks = %+v", checkList)
	}
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local", "allow_sudo": true}))
	if !host.AllowSudo {
		t.Fatalf("allow_sudo was not saved: %+v", host)
	}
	if response := request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{"rootkit"}}); response.Code != http.StatusBadRequest {
		t.Fatalf("an unknown check was accepted: %d", response.Code)
	}
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Malware}}))
	prompt := waitForPrompt(t, s, PromptSudo)
	request(t, s, http.MethodPost, "/api/scans/"+prompt.ScanID+"/respond", map[string]any{"value": "sudo-secret"})
	s.runner.wait()
	if strings.Join(gotChecks, ",") != checks.Malware || sudoPassword != "sudo-secret" {
		t.Fatalf("checks = %v, sudo password = %q", gotChecks, sudoPassword)
	}
	summary := decode[summary](t, request(t, s, http.MethodGet, "/api/summary", nil))
	malware := summary.Checks[checks.Malware]
	if malware == nil || malware.HostsWithFindings != 1 || malware.Severity.Critical != 1 || summary.ScannedHosts != 0 {
		t.Fatalf("a malware-only scan must not count as a package scan: %+v %+v", summary, malware)
	}
	detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil))
	if detail.Scan.Status != store.ScanSucceeded || detail.Report["check_results"] == nil {
		t.Fatalf("scan detail = %+v", detail)
	}

	patched := request(t, s, http.MethodPatch, "/api/hosts/"+host.ID, map[string]any{"allow_sudo": false})
	if patched.Code != http.StatusOK || decode[store.Host](t, patched).AllowSudo {
		t.Fatalf("PATCH allow_sudo: %d %s", patched.Code, patched.Body.String())
	}
}

func TestDecliningSudoContinuesTheScan(t *testing.T) {
	s := newTestServer(t, func(host store.Host, _ []string, options scan.Options) (map[string]any, error) {
		if _, err := options.SudoPassword(nil); err == nil {
			return nil, errors.New("expected the sudo prompt to be declined")
		}
		return map[string]any{"host_id": host.ID, "checks_run": []string{checks.Config}}, nil
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Config}}))
	waitForPrompt(t, s, PromptSudo)
	request(t, s, http.MethodPost, "/api/scans/"+started.ID+"/respond", map[string]any{"cancel": true})
	s.runner.wait()
	if detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil)); detail.Scan.Status != store.ScanSucceeded {
		t.Fatalf("declining sudo should not fail the scan: %+v", detail.Scan)
	}
}

func TestSkippedCheckIsNotCountedAsClean(t *testing.T) {
	s := newTestServer(t, func(host store.Host, selected []string, _ scan.Options) (map[string]any, error) {
		return map[string]any{
			"host_id": host.ID, "checks_run": selected,
			"check_results": map[string]any{checks.Antivirus: map[string]any{"status": "skipped", "findings": []any{}}},
		}, nil
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Antivirus}})
	s.runner.wait()
	totals := decode[summary](t, request(t, s, http.MethodGet, "/api/summary", nil)).Checks[checks.Antivirus]
	if totals == nil || totals.Hosts != 0 || totals.NotRun != 1 {
		t.Fatalf("a skipped check must not count as a checked host: %+v", totals)
	}
}

func TestLiveEventsStreamAndActivity(t *testing.T) {
	release := make(chan struct{})
	s := newTestServer(t, func(host store.Host, selected []string, options scan.Options) (map[string]any, error) {
		options.Progress(scan.Event{Kind: "phase", Phase: "connect", Message: "Connecting"})
		<-release
		options.Progress(scan.Event{Kind: "command", Phase: "malware", Message: "ps -eo pid=,user=,args=", Sudo: true})
		return map[string]any{"host_id": host.ID, "checks_run": selected}, nil
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Malware}}))

	activity := decode[[]Activity](t, request(t, s, http.MethodGet, "/api/activity", nil))
	if len(activity) != 1 || activity[0].ScanID != started.ID || activity[0].FinishedAt != "" {
		t.Fatalf("activity while running = %+v", activity)
	}
	close(release)
	s.runner.wait()

	log := decode[eventsResponse](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID+"/events", nil))
	if !log.Finished || len(log.Events) != 3 || log.Events[0].Message != "Connecting" || !log.Events[1].Sudo || log.Events[2].Kind != "done" {
		t.Fatalf("events = %+v", log)
	}
	resumed := decode[eventsResponse](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID+"/events?after=2", nil))
	if len(resumed.Events) != 1 || resumed.Events[0].Kind != "done" {
		t.Fatalf("resuming after event 2 = %+v", resumed)
	}
	activity = decode[[]Activity](t, request(t, s, http.MethodGet, "/api/activity", nil))
	if len(activity) != 1 || activity[0].Status != store.ScanSucceeded || activity[0].FinishedAt == "" {
		t.Fatalf("activity after finishing = %+v", activity)
	}
	if missing := request(t, s, http.MethodGet, "/api/scans/unknown/events", nil); missing.Code != http.StatusNotFound {
		t.Fatalf("unknown scan stream = %d", missing.Code)
	}
}

func TestSavedLogIsReplayedAfterRestart(t *testing.T) {
	s := newTestServer(t, func(host store.Host, selected []string, options scan.Options) (map[string]any, error) {
		options.Progress(scan.Event{Kind: "command", Phase: "config", Message: "ss -H -tuln"})
		return map[string]any{"host_id": host.ID, "checks_run": selected}, nil
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Config}}))
	s.runner.wait()

	// Simulate a restart: the in-memory copy is gone.
	s.runner.mu.Lock()
	s.runner.logs = make(map[string]*eventLog)
	s.runner.mu.Unlock()

	detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil))
	if !detail.Scan.HasLog {
		t.Fatalf("scan should report a saved log: %+v", detail.Scan)
	}
	saved := decode[eventsResponse](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID+"/events", nil))
	if !saved.Finished || len(saved.Events) != 2 || saved.Events[0].Message != "ss -H -tuln" || saved.Events[1].Kind != "done" {
		t.Fatalf("replayed log = %+v", saved)
	}
	if activity := decode[[]Activity](t, request(t, s, http.MethodGet, "/api/activity", nil)); len(activity) != 0 {
		t.Fatalf("a replayed log must not appear as activity: %+v", activity)
	}
}

func TestDeleteScanEndpoint(t *testing.T) {
	release := make(chan struct{})
	s := newTestServer(t, func(host store.Host, selected []string, _ scan.Options) (map[string]any, error) {
		<-release
		return map[string]any{"host_id": host.ID, "checks_run": selected}, nil
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Config}}))
	if response := request(t, s, http.MethodDelete, "/api/scans/"+started.ID, nil); response.Code != http.StatusConflict {
		t.Fatalf("deleting a running scan = %d", response.Code)
	}
	close(release)
	s.runner.wait()
	if response := request(t, s, http.MethodDelete, "/api/scans/"+started.ID, nil); response.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", response.Code, response.Body.String())
	}
	if response := request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil); response.Code != http.StatusNotFound {
		t.Fatalf("deleted scan still readable: %d", response.Code)
	}
	if response := request(t, s, http.MethodGet, "/api/scans/"+started.ID+"/events", nil); response.Code != http.StatusNotFound {
		t.Fatalf("deleted scan's log still readable: %d", response.Code)
	}
}

func TestScanIsFinalBeforeDoneIsPublished(t *testing.T) {
	s := newTestServer(t, func(host store.Host, selected []string, options scan.Options) (map[string]any, error) {
		options.Progress(scan.Event{Kind: "phase", Phase: "config", Message: "Security configuration"})
		return map[string]any{"host_id": host.ID, "checks_run": selected}, nil
	})
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{"checks": []string{checks.Config}}))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		log := decode[eventsResponse](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID+"/events", nil))
		if len(log.Events) > 0 && log.Events[len(log.Events)-1].Kind == "done" {
			detail := decode[scanDetail](t, request(t, s, http.MethodGet, "/api/scans/"+started.ID, nil))
			if detail.Scan.Status != store.ScanSucceeded || !detail.Scan.HasLog {
				t.Fatalf("done was visible before the scan was saved: %+v", detail.Scan)
			}
			s.runner.wait()
			saved, err := store.ScanEvents(started.ID)
			if err != nil || !strings.Contains(string(saved), `"kind":"done"`) {
				t.Fatalf("saved log lacks the done line: %s, %v", saved, err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the scan never published done")
}

func TestLocalHostRegistration(t *testing.T) {
	s := newTestServer(t, nil)
	capabilities := decode[capabilitiesResponse](t, request(t, s, http.MethodGet, "/api/capabilities", nil))
	response := request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"})
	host := decode[store.Host](t, response)
	if !capabilities.LocalScanning || response.Code != http.StatusCreated || host.Transport != store.TransportLocal || host.Address != capabilities.Hostname {
		t.Fatalf("local host = %d %+v, capabilities %+v", response.Code, host, capabilities)
	}
	if again := request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}); again.Code != http.StatusConflict {
		t.Fatalf("a second local host was accepted: %d", again.Code)
	}
}

func TestLocalHostRefusedWhereLocalScanningIsUnavailable(t *testing.T) {
	s := newTestServer(t, nil)
	s.localAvailable = func() error { return errors.New("local scanning is supported on Linux only; this machine runs darwin") }
	capabilities := decode[capabilitiesResponse](t, request(t, s, http.MethodGet, "/api/capabilities", nil))
	if capabilities.LocalScanning || !strings.Contains(capabilities.LocalReason, "Linux only") {
		t.Fatalf("capabilities = %+v", capabilities)
	}
	if response := request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}); response.Code != http.StatusBadRequest {
		t.Fatalf("local host on an unsupported system = %d", response.Code)
	}
}

func TestOnlyThisMachineCanBeAdded(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	s, err := New(fstest.MapFS{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.localAvailable = func() error { return nil }
	if response := request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "ssh"}); response.Code != http.StatusBadRequest {
		t.Fatalf("an SSH host was accepted: %d", response.Code)
	}
	if hosts := decode[[]store.HostSummary](t, request(t, s, http.MethodGet, "/api/hosts", nil)); len(hosts) != 0 {
		t.Fatalf("hosts = %+v", hosts)
	}
}
