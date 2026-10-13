package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
