package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/live"
	"deaconguard/internal/store"
)

func TestLiveAllowlist(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, bearer := enrollTestAgent(t, s, cookie, "web-01", "1.33.0")
	otherID, otherBearer := enrollTestAgent(t, s, cookie, "db-01", "1.27.0")
	for _, id := range []string{hostID, otherID} {
		if on := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + id + "/live", body: map[string]bool{"enabled": true}, cookie: cookie}); on.Code != http.StatusOK {
			t.Fatalf("on: %d", on.Code)
		}
	}
	add := func(body map[string]string) *store.LiveAllow {
		t.Helper()
		response := do(t, s, call{method: http.MethodPost, path: "/api/live/allowlist", body: body, cookie: cookie})
		if response.Code != http.StatusCreated {
			return nil
		}
		rule := decode[store.LiveAllow](t, response)
		return &rule
	}
	// A rule must name its alert's rule and something to match.
	for name, body := range map[string]map[string]string{
		"no rule":       {"program": "/usr/sbin/insmod"},
		"bad rule":      {"rule": "anything", "program": "/usr/sbin/insmod"},
		"only the rule": {"rule": live.RuleModule},
		"unknown host":  {"rule": live.RuleModule, "program": "/usr/sbin/insmod", "host_id": "nope"},
		"line break":    {"rule": live.RuleModule, "program": "/usr/sbin/insmod\nx"},
	} {
		if add(body) != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	viewer := signInAs(t, s, "viewer", store.RoleViewer)
	if refused := do(t, s, call{method: http.MethodPost, path: "/api/live/allowlist", cookie: viewer,
		body: map[string]string{"rule": live.RuleModule, "program": "/usr/sbin/insmod"}}); refused.Code != http.StatusForbidden {
		t.Fatalf("a viewer added a rule: %d", refused.Code)
	}

	modules := add(map[string]string{"rule": live.RuleModule, "program": "/usr/sbin/insmod", "path": "/opt/zfs/zfs.ko", "host_id": hostID, "note": "ZFS from the vendor"})
	builds := add(map[string]string{"rule": live.RuleTempProgram, "image": "acme/builder", "namespace": "ci"})
	if modules == nil || builds == nil || modules.Scope != "web-01" || builds.Scope != "All hosts" || modules.CreatedBy != "admin" {
		t.Fatalf("added: %+v %+v", modules, builds)
	}

	report := func(token, version string, body agentapi.LiveReport) agentapi.LiveReply {
		t.Helper()
		response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/live", body: body, bearer: token, headers: map[string]string{agentapi.HeaderVersion: version}})
		if response.Code != http.StatusOK {
			t.Fatalf("report: %d %s", response.Code, response.Body.String())
		}
		return decode[agentapi.LiveReply](t, response)
	}
	active := live.Status{State: live.StateActive, Since: time.Now()}
	// The agent gets the rules for its machine, and counts what it skipped.
	reply := report(bearer, "1.33.0", agentapi.LiveReport{Status: live.Status{State: live.StateActive, Since: time.Now(), Allowed: map[int64]uint64{modules.ID: 5}}})
	if len(reply.Allow) != 2 {
		t.Fatalf("rules sent: %+v", reply.Allow)
	}
	if reply := report(otherBearer, "1.27.0", agentapi.LiveReport{Status: active}); len(reply.Allow) != 1 || reply.Allow[0].ID != builds.ID {
		t.Fatalf("another host's rules: %+v", reply.Allow)
	}
	// An agent that doesn't know the rules sends what they expect: the
	// server skips it.
	report(otherBearer, "1.27.0", agentapi.LiveReport{Status: active, Alerts: []live.Alert{
		{Rule: live.RuleTempProgram, Severity: "HIGH", Title: "build step", Program: "/tmp/b/run", Image: "acme/builder:9", Namespace: "ci", Container: "job"},
		{Rule: live.RuleTempProgram, Severity: "HIGH", Title: "dropper", Program: "/tmp/x", Image: "acme/builder:9", Namespace: "prod", Container: "web",
			ContainerID: strings.Repeat("a", 64), Pod: "web-1"},
		{Rule: live.RuleModule, Severity: "HIGH", Title: "zfs on db", Program: "/usr/sbin/insmod", Path: "/opt/zfs/zfs.ko"},
	}})
	other := decode[liveResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/hosts/" + otherID + "/live", cookie: cookie}))
	if len(other.Alerts) != 2 || other.Alerts[0].Title != "zfs on db" || other.Alerts[1].Pod != "web-1" || other.Alerts[1].ContainerID == "" ||
		other.Allow.Rules != 1 || other.Allow.Skipped != 1 || other.Allow.LastAt == nil {
		t.Fatalf("db-01: %+v %+v", other.Alerts, other.Allow)
	}
	mine := decode[liveResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/hosts/" + hostID + "/live", cookie: cookie}))
	if mine.Allow.Rules != 2 || mine.Allow.Skipped != 5 {
		t.Fatalf("web-01: %+v", mine.Allow)
	}
	list := decode[[]store.LiveAllow](t, do(t, s, call{method: http.MethodGet, path: "/api/live/allowlist", cookie: viewer}))
	if len(list) != 2 || list[0].ID != builds.ID || list[0].Skipped != 1 || list[1].Skipped != 5 || list[1].Note != "ZFS from the vendor" {
		t.Fatalf("list: %+v", list)
	}

	// Changed, a rule keeps its count; removed, it's gone everywhere.
	changed := do(t, s, call{method: http.MethodPut, path: fmt.Sprintf("/api/live/allowlist/%d", builds.ID), cookie: cookie,
		body: map[string]string{"rule": live.RuleTempProgram, "image": "acme/builder:9", "namespace": "ci", "host_id": otherID}})
	if changed.Code != http.StatusOK || decode[store.LiveAllow](t, changed).Skipped != 1 || decode[store.LiveAllow](t, changed).Scope != "db-01" {
		t.Fatalf("changed: %d %s", changed.Code, changed.Body.String())
	}
	if removed := do(t, s, call{method: http.MethodDelete, path: fmt.Sprintf("/api/live/allowlist/%d", modules.ID), cookie: cookie}); removed.Code != http.StatusNoContent {
		t.Fatalf("removed: %d", removed.Code)
	}
	if again := do(t, s, call{method: http.MethodDelete, path: fmt.Sprintf("/api/live/allowlist/%d", modules.ID), cookie: cookie}); again.Code != http.StatusNotFound {
		t.Fatalf("removed twice: %d", again.Code)
	}
	if reply := report(bearer, "1.33.0", agentapi.LiveReport{Status: active}); len(reply.Allow) != 0 {
		t.Fatalf("web-01's rules after: %+v", reply.Allow)
	}
	// Counts for a rule removed meanwhile are dropped.
	report(bearer, "1.33.0", agentapi.LiveReport{Status: live.Status{State: live.StateActive, Since: time.Now(), Allowed: map[int64]uint64{modules.ID: 3}}})

	entries, err := store.AuditLog(50)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, entry := range entries {
		actions[entry.Action] += entry.Detail + "\n"
	}
	if !strings.Contains(actions["live.allow_add"], "on all hosts") || !strings.Contains(actions["live.allow_change"], "→") ||
		!strings.Contains(actions["live.allow_remove"], "program /usr/sbin/insmod, path /opt/zfs/zfs.ko; on web-01") {
		t.Fatalf("audit: %v", actions)
	}
}
