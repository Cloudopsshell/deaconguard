package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/store"
)

func TestUpdateCheck(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	asked, answer, status := 0, "1.34.0", http.StatusOK
	stable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer stable.Close()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s.updates.url, s.updates.version, s.updates.off = stable.URL, "1.33.1", false
	s.updates.now = func() time.Time { return now }
	get := func() updateResponse {
		t.Helper()
		response := do(t, s, call{method: http.MethodGet, path: "/api/update", cookie: cookie})
		if response.Code != http.StatusOK {
			t.Fatalf("GET /api/update: %d %s", response.Code, response.Body)
		}
		return decode[updateResponse](t, response)
	}
	set := func(on bool) int {
		t.Helper()
		return do(t, s, call{method: http.MethodPut, path: "/api/settings/updates", body: map[string]bool{"enabled": on}, cookie: cookie}).Code
	}

	// On by default, and nothing known before the first check.
	if status := get(); !status.Enabled || status.Available || status.Latest != "" || status.CheckedAt != nil || status.Current != "1.33.1" || !status.Release {
		t.Fatalf("before a check: %+v", status)
	}
	s.updates.checkDue(context.Background(), false)
	if status := get(); !status.Available || status.Latest != "1.34.0" || status.NotesURL != "https://docs.deaconguard.io/upgrade-notes/1.34.0" || status.CheckedAt == nil {
		t.Fatalf("after a check: %+v", status)
	}
	// Not asked again within the day.
	now = now.Add(23 * time.Hour)
	s.updates.checkDue(context.Background(), false)
	if asked != 1 {
		t.Fatalf("asked %d times within a day", asked)
	}
	// A failed check keeps the last answer, says why, and is retried after an hour.
	now = now.Add(2 * time.Hour)
	status = http.StatusServiceUnavailable
	s.updates.checkDue(context.Background(), false)
	if status := get(); asked != 2 || !status.Available || status.Latest != "1.34.0" || !strings.Contains(status.Error, "503") {
		t.Fatalf("after a failure: asked %d, %+v", asked, status)
	}
	now = now.Add(30 * time.Minute)
	s.updates.checkDue(context.Background(), false)
	now = now.Add(31 * time.Minute)
	status = http.StatusOK
	s.updates.checkDue(context.Background(), false)
	if status := get(); asked != 3 || status.Error != "" {
		t.Fatalf("the retry: asked %d, %+v", asked, status)
	}
	// On the newest release, nothing is offered.
	s.updates.version = "1.34.0"
	if status := get(); status.Available || status.NotesURL != "" || status.Latest != "1.34.0" {
		t.Fatalf("on the newest: %+v", status)
	}
	s.updates.version = "1.33.1"

	// Only admins see it or change it.
	viewer := signInAs(t, s, "viewer", store.RoleViewer)
	if refused := do(t, s, call{method: http.MethodGet, path: "/api/update", cookie: viewer}); refused.Code != http.StatusForbidden {
		t.Errorf("a viewer read the update: %d", refused.Code)
	}
	if refused := do(t, s, call{method: http.MethodPut, path: "/api/settings/updates", body: map[string]bool{"enabled": false}, cookie: viewer}); refused.Code != http.StatusForbidden {
		t.Errorf("a viewer changed the setting: %d", refused.Code)
	}

	// Off: nothing is asked, and what was learned is forgotten.
	if code := set(false); code != http.StatusOK {
		t.Fatalf("off: %d", code)
	}
	now = now.Add(48 * time.Hour)
	s.updates.checkDue(context.Background(), true)
	if status := get(); asked != 3 || status.Enabled || status.Available || status.Latest != "" {
		t.Fatalf("off: asked %d, %+v", asked, status)
	}
	if code := do(t, s, call{method: http.MethodPut, path: "/api/settings/updates", body: map[string]string{}, cookie: cookie}).Code; code != http.StatusBadRequest {
		t.Errorf("no enabled: %d", code)
	}
	if code := set(true); code != http.StatusOK {
		t.Fatalf("on: %d", code)
	}
	s.updates.checkDue(context.Background(), true)
	if status := get(); asked != 4 || !status.Available {
		t.Fatalf("on again: asked %d, %+v", asked, status)
	}

	// The environment's switch wins, and a local build never asks.
	s.updates.off = true
	s.updates.checkDue(context.Background(), true)
	if status := get(); asked != 4 || status.Enabled || !status.Managed || status.Available {
		t.Fatalf("off in the environment: asked %d, %+v", asked, status)
	}
	if code := set(true); code != http.StatusConflict {
		t.Errorf("turning on against the environment: %d", code)
	}
	s.updates.off, s.updates.version = false, "dev"
	s.updates.checkDue(context.Background(), true)
	if status := get(); asked != 4 || status.Release || status.Available {
		t.Fatalf("a local build: asked %d, %+v", asked, status)
	}

	// Both changes are audited.
	entries, err := store.AuditLog(50)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		if entry.Action == "settings.updates" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("%d audit entries, want 2", found)
	}
}
