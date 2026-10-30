package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/notify"
	"deaconguard/internal/store"
)

// hook records the webhook messages it receives, answering with status.
type hook struct {
	mu       sync.Mutex
	messages []map[string]any
	status   int
	server   *httptest.Server
}

func newHook(t *testing.T) *hook {
	t.Helper()
	h := &hook{status: http.StatusOK}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var message map[string]any
		_ = json.Unmarshal(body, &message)
		h.mu.Lock()
		h.messages = append(h.messages, message)
		status := h.status
		h.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *hook) events() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	events := []string{}
	for _, message := range h.messages {
		events = append(events, message["event"].(string))
	}
	return events
}

func (h *hook) last() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.messages[len(h.messages)-1]
}

func addChannel(t *testing.T, s *Server, cookie *http.Cookie, body map[string]any) channelView {
	t.Helper()
	response := do(t, s, call{method: http.MethodPost, path: "/api/notifications/channels", body: body, cookie: cookie})
	if response.Code != http.StatusCreated {
		t.Fatalf("add channel: %d %s", response.Code, response.Body.String())
	}
	return decode[channelView](t, response)
}

func completePackages(t *testing.T, host store.Host, findings ...map[string]any) string {
	t.Helper()
	scan, err := store.CreateScan(host, []string{store.CheckPackages})
	if err != nil {
		t.Fatal(err)
	}
	list := make([]any, 0, len(findings))
	for _, finding := range findings {
		list = append(list, finding)
	}
	if err := store.CompleteScan(scan.ID, map[string]any{"host_id": host.ID, "findings": list,
		"exploit_data": map[string]any{"kev": map[string]any{"available": true}}}); err != nil {
		t.Fatal(err)
	}
	return scan.ID
}

func kevFinding(cve string) map[string]any {
	return map[string]any{"id": cve, "package": "apache2", "installed_version": "1", "fixed_version": "2", "severity": "HIGH",
		"fix": "available", "priority": "exploited", "exploit": map[string]any{"kev": true}}
}

func TestChannelsAPIKeepsSecretsOnTheServer(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	for _, bad := range []map[string]any{
		{"name": "", "kind": "webhook", "config": map[string]any{"url": h.server.URL}},
		{"name": "x", "kind": "pager", "config": map[string]any{}},
		{"name": "x", "kind": "slack", "config": map[string]any{"url": "http://hooks.slack.com/x"}},
		{"name": "x", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "events": []string{"everything"}},
		{"name": "x", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "events": []string{"digest"}},
	} {
		if response := do(t, s, call{method: http.MethodPost, path: "/api/notifications/channels", body: bad, cookie: cookie}); response.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", bad, response.Code, response.Body.String())
		}
	}
	channel := addChannel(t, s, cookie, map[string]any{"name": "SOC webhook", "kind": "webhook",
		"config": map[string]any{"url": h.server.URL + "/very-secret-path", "secret": "s3cret"}, "events": []string{"exploited", "malware"}})
	if strings.Contains(channel.Config.URL, "very-secret") || channel.Config.Secret != "set" {
		t.Fatalf("secrets came back: %+v", channel.Config)
	}
	// Editing without the secrets keeps them.
	updated := do(t, s, call{method: http.MethodPatch, path: "/api/notifications/channels/" + channel.ID, cookie: cookie,
		body: map[string]any{"name": "SOC", "config": map[string]any{}, "events": []string{"exploited"}, "tags": []string{"prod"}}})
	if updated.Code != http.StatusOK {
		t.Fatalf("update: %d %s", updated.Code, updated.Body.String())
	}
	saved, _ := store.GetChannel(channel.ID)
	if !strings.Contains(saved.Config, "very-secret-path") || !strings.Contains(saved.Config, "s3cret") || saved.Name != "SOC" || saved.Tags[0] != "prod" {
		t.Fatalf("saved: %+v", saved)
	}
	tested := decode[store.Delivery](t, do(t, s, call{method: http.MethodPost, path: "/api/notifications/channels/" + channel.ID + "/test", cookie: cookie}))
	if tested.Status != store.DeliverySent || h.last()["event"] != notify.EventTest {
		t.Fatalf("test: %+v %v", tested, h.events())
	}
	h.status = http.StatusInternalServerError
	failed := decode[store.Delivery](t, do(t, s, call{method: http.MethodPost, path: "/api/notifications/channels/" + channel.ID + "/test", cookie: cookie}))
	if failed.Status != store.DeliveryFailed || !strings.Contains(failed.Error, "HTTP 500") {
		t.Fatalf("failed test: %+v", failed)
	}
	list := decode[notificationsResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/notifications", cookie: cookie}))
	if len(list.Channels) != 1 || len(list.Deliveries) != 2 || list.Channels[0].Last == nil || strings.Contains(list.Channels[0].Config.URL, "secret") {
		t.Fatalf("list: %+v", list)
	}
	if response := do(t, s, call{method: http.MethodPut, path: "/api/notifications/settings", cookie: cookie, body: map[string]any{"dashboard_url": "javascript:alert(1)"}}); response.Code != http.StatusBadRequest {
		t.Fatalf("bad dashboard address: %d", response.Code)
	}
	if response := do(t, s, call{method: http.MethodPut, path: "/api/notifications/settings", cookie: cookie, body: map[string]any{"dashboard_url": "https://dg.example.com/"}}); response.Code != http.StatusOK {
		t.Fatalf("dashboard address: %d", response.Code)
	}
	if link("/hosts/x") != "https://dg.example.com/hosts/x" {
		t.Fatalf("link: %q", link("/hosts/x"))
	}
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/notifications/channels/" + channel.ID, cookie: cookie}); response.Code != http.StatusOK {
		t.Fatalf("delete: %d", response.Code)
	}
}

func TestScansNotifyOnlyWhatIsNew(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	addChannel(t, s, cookie, map[string]any{"name": "all", "kind": "webhook", "config": map[string]any{"url": h.server.URL},
		"events": []string{"exploited", "critical", "scan_failed", "agent_offline", "malware"}})
	addChannel(t, s, cookie, map[string]any{"name": "prod only", "kind": "webhook", "config": map[string]any{"url": h.server.URL},
		"events": []string{"exploited"}, "tags": []string{"prod"}})
	host, err := store.AddLocalHost("web-01", "root")
	if err != nil {
		t.Fatal(err)
	}
	deliver := func() { s.deliverDue(context.Background(), time.Now()) }

	first := completePackages(t, host, kevFinding("CVE-2024-38475"))
	s.scanFinished(host, first, nil)
	deliver()
	if events := h.events(); len(events) != 1 || events[0] != notify.EventExploited {
		t.Fatalf("first scan: %v (the prod-only channel must stay quiet)", events)
	}
	data := h.last()["data"].(map[string]any)
	if cves := data["cves"].([]any); len(cves) != 1 || cves[0] != "CVE-2024-38475" {
		t.Fatalf("cves: %v", data)
	}

	// The same finding again is not news; a new one is.
	second := completePackages(t, host, kevFinding("CVE-2024-38475"))
	s.scanFinished(host, second, nil)
	deliver()
	if len(h.events()) != 1 {
		t.Fatalf("a repeated finding was sent again: %v", h.events())
	}
	if _, err := store.SetHostTags(host.ID, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	third := completePackages(t, host, kevFinding("CVE-2024-38475"), kevFinding("CVE-2023-4911"))
	s.scanFinished(host, third, nil)
	deliver()
	if events := h.events(); len(events) != 3 {
		t.Fatalf("a new finding on a prod host goes to both channels: %v", events)
	}
	if cves := h.last()["data"].(map[string]any)["cves"].([]any); len(cves) != 1 || cves[0] != "CVE-2023-4911" {
		t.Fatalf("only the new CVE: %v", cves)
	}

	s.scanFinished(host, "scan-x", errors.New("the agent went away"))
	s.agentQuiet(host.ID, host.Address, time.Now().Add(-3*time.Minute))
	deliver()
	if events := h.events(); events[3] != notify.EventScanFailed || events[4] != notify.EventAgentOffline {
		t.Fatalf("events: %v", events)
	}
}

func TestDeliveriesRetryThenFail(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	h.status = http.StatusBadGateway
	channel := addChannel(t, s, cookie, map[string]any{"name": "flaky", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "events": []string{"agent_offline"}})
	s.agentQuiet("h1", "web-01", time.Now())
	now := time.Now()
	for attempt := 0; attempt <= len(deliveryRetries); attempt++ {
		s.deliverDue(context.Background(), now)
		now = now.Add(time.Hour)
	}
	deliveries, err := store.Deliveries(channel.ID, 10)
	if err != nil || len(deliveries) != 1 || deliveries[0].Status != store.DeliveryFailed || deliveries[0].Attempts != len(deliveryRetries)+1 {
		t.Fatalf("deliveries: %+v %v", deliveries, err)
	}
	if len(h.events()) != len(deliveryRetries)+1 {
		t.Fatalf("attempts: %d", len(h.events()))
	}
	// Turned-off channels don't get queued messages.
	turnedOff := false
	do(t, s, call{method: http.MethodPatch, path: "/api/notifications/channels/" + channel.ID, cookie: cookie,
		body: map[string]any{"name": "flaky", "config": map[string]any{}, "events": []string{"agent_offline"}, "enabled": &turnedOff}})
	s.agentQuiet("h1", "web-01", time.Now())
	s.deliverDue(context.Background(), time.Now())
	if len(h.events()) != len(deliveryRetries)+1 {
		t.Fatal("a turned-off channel was sent to")
	}
}

func TestDigestGoesOutWhenDue(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	channel := addChannel(t, s, cookie, map[string]any{"name": "weekly", "kind": "webhook", "config": map[string]any{"url": h.server.URL},
		"digest": "weekly", "digest_days": []int{1}, "digest_time": "08:00", "timezone": "Europe/London"})
	if channel.NextDigestAt == "" || !strings.Contains(strings.Join(channel.Events, ","), "digest") {
		t.Fatalf("channel: %+v", channel)
	}
	host, _ := store.AddLocalHost("web-01", "root")
	completePackages(t, host, kevFinding("CVE-2024-38475"))
	if err := store.SetNextDigest(channel.ID, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	s.sendDueDigests(time.Now())
	s.deliverDue(context.Background(), time.Now())
	if events := h.events(); len(events) != 1 || events[0] != notify.EventDigest {
		t.Fatalf("events: %v", events)
	}
	data := h.last()["data"].(map[string]any)
	if data["known_exploited"].(float64) != 1 || !strings.HasPrefix(h.last()["title"].(string), "Weekly summary") {
		t.Fatalf("digest: %v", h.last())
	}
	saved, _ := store.GetChannel(channel.ID)
	if next, err := time.Parse(time.RFC3339, saved.NextDigestAt); err != nil || !next.After(time.Now()) || next.In(mustZone(t, "Europe/London")).Weekday() != time.Monday {
		t.Fatalf("next digest: %q", saved.NextDigestAt)
	}
	// Not due again until then.
	s.sendDueDigests(time.Now())
	s.deliverDue(context.Background(), time.Now())
	if len(h.events()) != 1 {
		t.Fatal("the digest went out twice")
	}
	if message, err := digest(saved); err != nil || message.Attachment != nil {
		t.Fatalf("a webhook digest has no attachment: %v", err)
	}
	saved.Kind = notify.Email
	message, err := digest(saved)
	if err != nil || message.Attachment == nil || !strings.Contains(string(message.Attachment.Data), "CVE-2024-38475") {
		t.Fatalf("attachment: %v", err)
	}
}

func mustZone(t *testing.T, name string) *time.Location {
	zone, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return zone
}

func TestMaintenanceHoldsBackNotificationsAndScans(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	addChannel(t, s, cookie, map[string]any{"name": "all", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "events": []string{"agent_offline"}})
	host, _ := store.AddLocalHost("web-01", "root")
	if _, err := store.SetHostTags(host.ID, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	response := do(t, s, call{method: http.MethodPost, path: "/api/maintenance", cookie: cookie, body: map[string]any{
		"name": "Patching", "tags": []string{"prod"}, "starts_at": now.Add(-time.Minute).Format(time.RFC3339),
		"ends_at": now.Add(time.Hour).Format(time.RFC3339), "skip_scans": true}})
	if response.Code != http.StatusCreated {
		t.Fatalf("add window: %d %s", response.Code, response.Body.String())
	}
	window := decode[store.MaintenanceWindow](t, response)
	s.agentQuiet(host.ID, host.Address, now)
	s.deliverDue(context.Background(), time.Now())
	if len(h.events()) != 0 {
		t.Fatalf("a notification went out during maintenance: %v", h.events())
	}
	schedule, err := store.SaveSchedule(store.Schedule{Name: "nightly", Enabled: true, Checks: []string{"packages"}, AllHosts: true, Days: []int{1}, Time: "02:00", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	if started, skipped := s.runSchedule(schedule); started != 0 || skipped != 1 {
		t.Fatalf("schedule during maintenance: %d started, %d skipped", started, skipped)
	}
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/maintenance/" + window.ID, cookie: cookie}); response.Code != http.StatusOK {
		t.Fatalf("delete: %d", response.Code)
	}
	s.agentQuiet(host.ID, host.Address, now)
	s.deliverDue(context.Background(), time.Now())
	if len(h.events()) != 1 {
		t.Fatalf("after the window: %v", h.events())
	}
}

func TestOverdueCountsEachCVEOncePerHost(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	host, _ := store.AddLocalHost("web-01", "root")
	second := kevFinding("CVE-2024-38475")
	second["package"] = "apache2-bin"
	completePackages(t, host, kevFinding("CVE-2024-38475"), second)
	past := time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	db, err := sql.Open("sqlite", store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE host_cve_seen SET first_seen = ?", past); err != nil {
		t.Fatal(err)
	}
	result := decode[summary](t, do(t, s, call{method: http.MethodGet, path: "/api/summary", cookie: cookie}))
	if !result.SLA.Enabled || result.SLA.Overdue != 1 || result.SLA.HostsOverdue != 1 {
		t.Fatalf("sla: %+v", result.SLA)
	}
}

// completeChecks stores a successful scan of host with these check results.
func completeChecks(t *testing.T, host store.Host, results map[string]any) store.Scan {
	t.Helper()
	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	ids, err := checks.Normalize(ids)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.CreateScan(host, ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteScan(record.ID, map[string]any{"host_id": host.ID, "checks_run": ids, "check_results": results}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // scans started within one second sort by their IDs
	record, _ = store.GetScan(record.ID)
	return record
}

func containerResult(containers ...map[string]any) map[string]any {
	return map[string]any{"status": "completed", "notes": []string{}, "findings": []any{}, "containers": containers}
}

func container(name, image string, findings ...map[string]any) map[string]any {
	return map[string]any{"id": name, "name": name, "image": image, "state": "running", "findings": findings,
		"severity": map[string]int{}, "exploited": 0, "fixable": 0, "packages": 1, "libraries": 0}
}

func containerCVE(cve, severity string, exploited, fixable bool) map[string]any {
	return map[string]any{"rule": cve, "severity": severity, "title": cve, "detail": "", "evidence": "", "exploited": exploited, "fixable": fixable}
}

func TestContainerAndConfigFindingsAreNotified(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	addChannel(t, s, cookie, map[string]any{"name": "slack", "kind": "webhook", "config": map[string]any{"url": h.server.URL},
		"events": []string{"exploited", "critical", "config"}})
	host, err := store.AddLocalHost("web-01", "root")
	if err != nil {
		t.Fatal(err)
	}
	deliver := func() { s.deliverDue(context.Background(), time.Now()) }
	kev := containerCVE("CVE-2023-44487", "HIGH", true, true)
	critical := containerCVE("CVE-2024-6387", "CRITICAL", false, true)
	unfixed := containerCVE("CVE-2024-0001", "CRITICAL", false, false)
	passwords := map[string]any{"rule": "config.ssh-password-auth", "severity": "MEDIUM", "title": "SSH password login is enabled", "detail": "", "evidence": ""}
	firewall := map[string]any{"rule": "config.firewall", "severity": "LOW", "title": "No host firewall", "detail": "", "evidence": ""}
	config := func(findings ...map[string]any) map[string]any {
		return map[string]any{"status": "completed", "notes": []string{}, "findings": findings}
	}

	first := completeChecks(t, host, map[string]any{
		checks.Containers: containerResult(container("nginx", "nginx:1.27.0", kev, critical, unfixed), container("alpine", "alpine:3.22")),
		checks.Config:     config(passwords, firewall),
	})
	s.scanFinished(host, first.ID, nil)
	deliver()
	if events := strings.Join(h.events(), ","); events != "exploited,critical,config" {
		t.Fatalf("first scan: %s", events)
	}
	h.mu.Lock()
	exploited, criticalMessage, configMessage := h.messages[0], h.messages[1], h.messages[2]
	h.mu.Unlock()
	if exploited["title"] != "web-01: 1 new vulnerability known to be exploited in running containers" ||
		!strings.Contains(strings.Join(anyStrings(exploited["lines"]), "\n"), "nginx:1.27.0: CVE-2023-44487") {
		t.Fatalf("exploited: %v", exploited)
	}
	// A critical vulnerability without a fix isn't reported as one with a fix.
	if criticalMessage["title"] != "web-01: 1 new critical vulnerability with a fix in running containers" {
		t.Fatalf("critical: %v", criticalMessage)
	}
	// Medium and up for configuration; the low finding is left out.
	if configMessage["title"] != "web-01: 1 new configuration finding" || configMessage["level"] != notify.LevelWarning {
		t.Fatalf("config: %v", configMessage)
	}

	// The same image restarted, under a new container, is not news; a new
	// image with the same CVE is.
	second := completeChecks(t, host, map[string]any{
		checks.Containers: containerResult(container("nginx-2", "nginx:1.27.0", kev, critical), container("api", "api:7", kev)),
		checks.Config:     config(passwords, firewall),
	})
	s.scanFinished(host, second.ID, nil)
	deliver()
	if events := h.events(); len(events) != 4 || events[3] != notify.EventExploited {
		t.Fatalf("second scan: %v", events)
	}
	if title := h.last()["title"]; title != "web-01: 1 new vulnerability known to be exploited in running containers" ||
		!strings.Contains(strings.Join(anyStrings(h.last()["lines"]), "\n"), "api:7: CVE-2023-44487") {
		t.Fatalf("second: %v", h.last())
	}
}

func TestScanResultsSumUpEveryScan(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	addChannel(t, s, cookie, map[string]any{"name": "every scan", "kind": "webhook", "config": map[string]any{"url": h.server.URL},
		"events": []string{"scan_results"}})
	quiet := newHook(t)
	addChannel(t, s, cookie, map[string]any{"name": "default", "kind": "webhook", "config": map[string]any{"url": quiet.server.URL},
		"events": []string{"exploited", "malware", "config"}})
	host, _ := store.AddLocalHost("web-01", "root")
	clean := map[string]any{"status": "completed", "notes": []string{}, "findings": []any{}}
	record := completeChecks(t, host, map[string]any{checks.Malware: clean, checks.Config: clean})
	s.scanFinished(host, record.ID, nil)
	s.deliverDue(context.Background(), time.Now())
	if events := h.events(); len(events) != 1 || events[0] != notify.EventScanResults {
		t.Fatalf("events: %v", events)
	}
	lines := strings.Join(anyStrings(h.last()["lines"]), "\n")
	if !strings.HasPrefix(h.last()["title"].(string), "web-01: scan finished") || h.last()["level"] != notify.LevelInfo ||
		!strings.Contains(lines, "Malware & compromise indicators: nothing found") || !strings.Contains(lines, "Security configuration: nothing found") {
		t.Fatalf("summary: %v", h.last())
	}
	// A clean scan sends nothing to channels without the event.
	if len(quiet.events()) != 0 {
		t.Fatalf("quiet channel: %v", quiet.events())
	}
}

func TestDigestCountsRunningContainers(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	channel := addChannel(t, s, cookie, map[string]any{"name": "daily", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "digest": "daily", "digest_time": "08:00", "timezone": "UTC"})
	host, _ := store.AddLocalHost("web-01", "root")
	nginx := container("nginx", "nginx:1.27.0")
	nginx["exploited"] = 3
	nginx["fixable_severity"] = map[string]int{"CRITICAL": 2}
	twin := container("nginx-b", "nginx:1.27.0")
	twin["exploited"] = 3
	completeChecks(t, host, map[string]any{checks.Containers: containerResult(nginx, twin, container("alpine", "alpine:3.22"))})
	saved, _ := store.GetChannel(channel.ID)
	message, err := digest(saved)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(message.Lines, "\n")
	if !strings.Contains(lines, "Running containers: 2 images on 1 host; 3 known exploited, 2 critical with a fix in the image.") || message.Level != notify.LevelWarning {
		t.Fatalf("digest: %s (%s)", lines, message.Level)
	}
}

func TestBusyAgentsAreNotOffline(t *testing.T) {
	var quiet []string
	p := presence{seen: map[string]presenceEntry{}, onQuiet: func(id, _ string, _ time.Time) { quiet = append(quiet, id) }}
	p.seen["scanning"] = presenceEntry{address: "db-01", at: time.Now().Add(-10 * time.Minute)}
	p.seen["gone"] = presenceEntry{address: "web-01", at: time.Now().Add(-10 * time.Minute)}
	p.sweep(time.Now(), map[string]bool{"scanning": true})
	if len(quiet) != 1 || quiet[0] != "gone" {
		t.Fatalf("quiet: %v", quiet)
	}
	// Once its scan is over, a quiet agent counts as gone.
	p.sweep(time.Now(), nil)
	if len(quiet) != 2 || quiet[1] != "scanning" {
		t.Fatalf("quiet: %v", quiet)
	}
}

func anyStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, item.(string))
	}
	return out
}
