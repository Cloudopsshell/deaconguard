package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/live"
	"deaconguard/internal/store"
)

func TestLiveDetection(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, bearer := enrollTestAgent(t, s, cookie, "web-01", "1.27.0")
	oldID, _ := enrollTestAgent(t, s, cookie, "old-01", "1.26.0")

	get := func(id string) liveResponse {
		t.Helper()
		response := do(t, s, call{method: http.MethodGet, path: "/api/hosts/" + id + "/live", cookie: cookie})
		if response.Code != http.StatusOK {
			t.Fatalf("live: %d %s", response.Code, response.Body.String())
		}
		return decode[liveResponse](t, response)
	}
	if status := get(hostID).Status; status == nil || status.State != store.LiveWaiting || !status.Enabled {
		t.Fatalf("before the first report: %+v", status)
	}
	if status := get(oldID).Status; status == nil || status.State != store.LiveAgentTooOld {
		t.Fatalf("1.26.0 agent: %+v", status)
	}

	report := func(body agentapi.LiveReport) agentapi.LiveReply {
		t.Helper()
		response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/live", body: body, bearer: bearer, headers: map[string]string{agentapi.HeaderVersion: "1.27.0"}})
		if response.Code != http.StatusOK {
			t.Fatalf("report: %d %s", response.Code, response.Body.String())
		}
		return decode[agentapi.LiveReply](t, response)
	}
	active := live.Status{State: live.StateActive, Since: time.Now(), Kernel: "6.8.0", EventsLastHour: 1200, CPUPercent: 0.3, MemoryBytes: 30 << 20}
	reply := report(agentapi.LiveReport{Status: active, Alerts: []live.Alert{
		{Rule: live.RuleServiceShell, Severity: "CRITICAL", Title: "A shell started under php-fpm8.3", Program: "/bin/sh", Parent: "php-fpm8.3", User: "www-data"},
		{Rule: live.RuleTempProgram, Severity: "LOW", Title: "Test alert: live detection works end to end", Test: true},
	}})
	if !reply.Enabled || reply.Test {
		t.Fatalf("reply: %+v", reply)
	}
	detail := get(hostID)
	if detail.Status.State != live.StateActive || detail.Status.EventsLastHour != 1200 || detail.Status.Alerts24h.Critical != 1 || len(detail.Alerts) != 2 ||
		!detail.Alerts[0].Test || detail.Alerts[1].Parent != "php-fpm8.3" {
		t.Fatalf("after a report: %+v %+v", *detail.Status, detail.Alerts)
	}

	// The test button reaches the agent once.
	if asked := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + hostID + "/live/test", cookie: cookie}); asked.Code != http.StatusAccepted {
		t.Fatalf("test: %d %s", asked.Code, asked.Body.String())
	}
	if reply := report(agentapi.LiveReport{Status: active}); !reply.Test {
		t.Fatal("the agent wasn't asked for a test alert")
	}
	if reply := report(agentapi.LiveReport{Status: active}); reply.Test {
		t.Fatal("the agent was asked twice")
	}
	if refused := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + oldID + "/live/test", cookie: cookie}); refused.Code != http.StatusConflict {
		t.Fatalf("test on a 1.26.0 agent: %d", refused.Code)
	}

	// Turned off, the agent is told so, and the host shows it.
	off := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + hostID + "/live", body: map[string]bool{"enabled": false}, cookie: cookie})
	if off.Code != http.StatusOK || decode[liveResponse](t, off).Status.State != live.StateOff {
		t.Fatalf("off: %d %s", off.Code, off.Body.String())
	}
	if reply := report(agentapi.LiveReport{Status: active}); reply.Enabled {
		t.Fatal("the agent wasn't told to stop")
	}
	if missing := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + hostID + "/live", body: map[string]any{}, cookie: cookie}); missing.Code != http.StatusBadRequest {
		t.Fatalf("no enabled: %d", missing.Code)
	}

	// Too many alerts at once are refused; hosts list the status.
	var many []live.Alert
	for range agentapi.MaxLiveAlerts + 1 {
		many = append(many, live.Alert{Rule: live.RuleMiner, Severity: "CRITICAL", Title: "x"})
	}
	if refused := do(t, s, call{method: http.MethodPost, path: "/agent/v1/live", body: agentapi.LiveReport{Alerts: many}, bearer: bearer, headers: map[string]string{agentapi.HeaderVersion: "1.27.0"}}); refused.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too many alerts: %d", refused.Code)
	}
	summaries, err := store.HostSummaries()
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range summaries {
		if summary.ID == hostID && (summary.Live == nil || summary.Live.State != live.StateOff) {
			t.Fatalf("summary: %+v", summary.Live)
		}
	}
	if anonymous := do(t, s, call{method: http.MethodPost, path: "/agent/v1/live", body: agentapi.LiveReport{}}); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous report: %d", anonymous.Code)
	}
	if !strings.Contains(get(oldID).Status.Reason, "1.27.0") {
		t.Fatal("no reason for the old agent")
	}
}
