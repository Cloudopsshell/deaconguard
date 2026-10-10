package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/store"
)

func TestSchedulesStartScansWhenDue(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	newHost, _ := enrollTestAgent(t, s, cookie, "web-01", "0.8.0")
	oldHost, _ := enrollTestAgent(t, s, cookie, "old-01", "0.4.2")

	if anonymous := do(t, s, call{method: http.MethodGet, path: "/api/schedules"}); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("schedules without signing in: %d", anonymous.Code)
	}
	for name, body := range map[string]map[string]any{
		"no name":   {"checks": []string{"packages"}, "all_hosts": true, "days": []int{1}, "time": "02:30", "timezone": "UTC"},
		"no days":   {"name": "x", "checks": []string{"packages"}, "all_hosts": true, "days": []int{}, "time": "02:30", "timezone": "UTC"},
		"bad zone":  {"name": "x", "checks": []string{"packages"}, "all_hosts": true, "days": []int{1}, "time": "02:30", "timezone": "Nowhere/Here"},
		"bad check": {"name": "x", "checks": []string{"nope"}, "all_hosts": true, "days": []int{1}, "time": "02:30", "timezone": "UTC"},
		"no hosts":  {"name": "x", "checks": []string{"packages"}, "host_ids": []string{}, "days": []int{1}, "time": "02:30", "timezone": "UTC"},
		"bad host":  {"name": "x", "checks": []string{"packages"}, "host_ids": []string{"nope"}, "days": []int{1}, "time": "02:30", "timezone": "UTC"},
	} {
		if refused := do(t, s, call{method: http.MethodPost, path: "/api/schedules", body: body, cookie: cookie}); refused.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, refused.Code, refused.Body.String())
		}
	}

	created := do(t, s, call{method: http.MethodPost, path: "/api/schedules", cookie: cookie, body: map[string]any{
		"name": "Nightly", "checks": []string{"packages", "yara"}, "all_hosts": true,
		"days": []int{0, 1, 2, 3, 4, 5, 6}, "time": "02:30", "timezone": "Europe/Stockholm",
	}})
	view := decode[scheduleView](t, created)
	if created.Code != http.StatusCreated || view.Description != "Every day at 02:30 (Europe/Stockholm)" || view.NextRunAt == "" || !view.RunAsRoot ||
		strings.Join(view.Checks, ",") != "packages,antivirus,yara" {
		t.Fatalf("create: %d %+v", created.Code, view)
	}
	host := decode[hostDetail](t, do(t, s, call{method: http.MethodGet, path: "/api/hosts/" + newHost, cookie: cookie}))
	if host.NextScan == nil || host.NextScan.Schedule != "Nightly" || host.NextScan.At != view.NextRunAt {
		t.Fatalf("host's next scan = %+v", host.NextScan)
	}

	// Nothing is due before the next run; at it, scans start and the next run moves on a day.
	next, _ := time.Parse(time.RFC3339, view.NextRunAt)
	s.runDueSchedules(next.Add(-time.Minute))
	if _, busy, _ := store.UnfinishedScan(newHost); busy {
		t.Fatal("a scan started before the schedule was due")
	}
	s.runDueSchedules(next)
	if _, busy, _ := store.UnfinishedScan(newHost); !busy {
		t.Fatal("the schedule did not start a scan")
	}
	// The 0.4.2 agent cannot run the advanced scan: skipped and logged, not failed silently.
	if _, busy, _ := store.UnfinishedScan(oldHost); busy {
		t.Fatal("the schedule started an advanced scan on a 0.4.2 agent")
	}
	skipped, _, _ := store.Logs(store.LogQuery{HostID: oldHost, Search: "skipped"})
	if len(skipped) != 1 || !strings.Contains(skipped[0].Message, `Schedule "Nightly" skipped old-01`) {
		t.Fatalf("skip log = %+v", skipped)
	}
	after, _ := store.GetSchedule(view.ID)
	if after.LastRunAt == "" || after.NextRunAt != next.Add(24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("after the run: last %q, next %q", after.LastRunAt, after.NextRunAt)
	}
	// A run that is still queued is not started twice.
	s.runSchedule(after)
	inProgress, _, _ := store.Logs(store.LogQuery{HostID: newHost, Search: "already queued"})
	if len(inProgress) != 1 {
		t.Fatalf("in-progress log = %+v", inProgress)
	}

	// Turning it off clears the next run; deleting it removes it.
	off := false
	updated := decode[scheduleView](t, do(t, s, call{method: http.MethodPatch, path: "/api/schedules/" + view.ID, cookie: cookie, body: scheduleRequest{
		Name: "Nightly", Enabled: &off, RunAsRoot: &off, Checks: []string{"packages"}, AllHosts: true, Days: []int{1}, Time: "03:00", Timezone: "UTC",
	}}))
	if updated.Enabled || updated.NextRunAt != "" || updated.RunAsRoot {
		t.Fatalf("disabled schedule = %+v", updated)
	}
	if deleted := do(t, s, call{method: http.MethodDelete, path: "/api/schedules/" + view.ID, cookie: cookie}); deleted.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", deleted.Code)
	}
	audit, _ := store.AuditLog(100)
	actions := map[string]bool{}
	for _, entry := range audit {
		actions[entry.Action+" "+entry.Actor] = true
	}
	details := map[string]string{}
	for _, entry := range audit {
		details[entry.Action] = entry.Detail
	}
	if !strings.HasSuffix(details["schedule.create"], ", with root") || !strings.Contains(details["schedule.update"], ", without root") {
		t.Errorf("audit details = %q / %q", details["schedule.create"], details["schedule.update"])
	}
	for _, want := range []string{"schedule.create admin", "schedule.update admin", "schedule.delete admin", "scan.start schedule: Nightly"} {
		if !actions[want] {
			t.Errorf("audit log lacks %q", want)
		}
	}
}
