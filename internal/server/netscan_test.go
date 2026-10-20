package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/iac"
	"deaconguard/internal/netscan"
	"deaconguard/internal/store"
)

func TestNetworkTargetsAreScanned(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	channel := addChannel(t, s, cookie, map[string]any{"name": "exposure", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "events": []string{"exposure"}})
	redis := iac.Finding{Rule: "DG-NET-001", Severity: "HIGH", Title: "10.0.0.2: Redis answers on port 6379", File: "10.0.0.2:6379"}
	docker := iac.Finding{Rule: "DG-NET-002", Severity: "CRITICAL", Title: "10.0.0.3: Docker API answers on port 2375", File: "10.0.0.3:2375"}
	findings := []iac.Finding{redis}
	var scanned []string
	s.netScans.scan = func(ctx context.Context, target store.NetworkTarget) (netscan.Result, error) {
		scanned = append(scanned, strings.Join(target.Targets, ","))
		return netscan.Result{Addresses: 254, Hosts: []netscan.Host{{Address: "10.0.0.2", Services: []netscan.Service{{Port: 6379, Name: "Redis"}}}},
			Findings: findings}, nil
	}

	for name, body := range map[string]map[string]any{
		"no name":      {"targets": []string{"10.0.0.0/24"}},
		"no targets":   {"name": "x", "targets": []string{}},
		"too large":    {"name": "x", "targets": []string{"10.0.0.0/16"}},
		"bad target":   {"name": "x", "targets": []string{"not a host!"}},
		"bad ports":    {"name": "x", "targets": []string{"10.0.0.1"}, "ports": "0"},
		"bad interval": {"name": "x", "targets": []string{"10.0.0.1"}, "interval_hours": 5},
		"over 4096":    {"name": "x", "targets": []string{"10.0.0.0/20", "10.1.0.1"}},
	} {
		if refused := do(t, s, call{method: http.MethodPost, path: "/api/network-targets", body: body, cookie: cookie}); refused.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, refused.Code, refused.Body.String())
		}
	}
	created := do(t, s, call{method: http.MethodPost, path: "/api/network-targets", cookie: cookie, body: map[string]any{
		"name": "Office", "targets": []string{"10.0.0.0/24", " gw.office.example ", "10.0.0.0/24"}, "interval_hours": 24}})
	target := decode[store.NetworkTarget](t, created)
	if created.Code != http.StatusCreated || strings.Join(target.Targets, ",") != "10.0.0.0/24,gw.office.example" || !target.TLS ||
		target.Latest == nil || target.Latest.Status != store.ScanQueued {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	if again := do(t, s, call{method: http.MethodPost, path: "/api/network-targets", cookie: cookie, body: map[string]any{"name": "office", "targets": []string{"10.0.0.1"}}}); again.Code != http.StatusConflict {
		t.Fatalf("the same name: %d", again.Code)
	}
	s.runQueuedNetworkScans(context.Background())
	detail := do(t, s, call{method: http.MethodGet, path: "/api/network-targets/" + target.ID, cookie: cookie})
	var view struct {
		Target store.NetworkTarget `json:"target"`
		Scans  []store.NetworkScan `json:"scans"`
	}
	json.Unmarshal(detail.Body.Bytes(), &view)
	latest := view.Target.Latest
	if len(scanned) != 1 || latest == nil || latest.Status != store.ScanSucceeded || latest.Hosts != 1 || latest.OpenPorts != 1 || latest.Severity.High != 1 {
		t.Fatalf("after the scan: %v %+v", scanned, latest)
	}
	full := decode[store.NetworkScan](t, do(t, s, call{method: http.MethodGet, path: "/api/network-scans/" + latest.ID, cookie: cookie}))
	var result netscan.Result
	if err := json.Unmarshal(full.Result, &result); err != nil || result.Hosts[0].Services[0].Name != "Redis" {
		t.Fatalf("result: %s", full.Result)
	}

	// Due again a day after the last scan, not before.
	started, _ := time.Parse(time.RFC3339, latest.StartedAt)
	s.queueDueNetworkScans(started.Add(23 * time.Hour))
	if target, _ := store.GetNetworkTarget(target.ID); target.Latest.Status != store.ScanSucceeded {
		t.Fatal("queued before it was due")
	}
	findings = []iac.Finding{redis, docker}
	s.queueDueNetworkScans(started.Add(25 * time.Hour))
	s.runQueuedNetworkScans(context.Background())
	if target, _ := store.GetNetworkTarget(target.ID); target.Latest.StartedBy != "schedule" || target.Latest.Severity.Critical != 1 {
		t.Fatalf("scheduled scan: %+v", target.Latest)
	}
	// Notified: the first scan's Redis, then only the new Docker API.
	deliveries, _ := store.Deliveries(channel.ID, 10)
	if len(deliveries) != 2 || !strings.Contains(deliveries[0].Title+deliveries[1].Title, "Network Office: 1 new critical or high finding") {
		t.Fatalf("deliveries: %+v", deliveries)
	}

	if edited := do(t, s, call{method: http.MethodPatch, path: "/api/network-targets/" + target.ID, cookie: cookie,
		body: map[string]any{"name": "Office", "targets": []string{"10.0.0.0/25"}, "tls": false, "interval_hours": 0}}); edited.Code != http.StatusOK ||
		decode[store.NetworkTarget](t, edited).TLS {
		t.Fatalf("edit: %d %s", edited.Code, edited.Body.String())
	}
	if removed := do(t, s, call{method: http.MethodDelete, path: "/api/network-targets/" + target.ID, cookie: cookie}); removed.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", removed.Code)
	}
	if gone := do(t, s, call{method: http.MethodGet, path: "/api/network-scans/" + latest.ID, cookie: cookie}); gone.Code != http.StatusNotFound {
		t.Fatalf("a deleted target's scan: %d", gone.Code)
	}
}
