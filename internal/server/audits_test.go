package server

import (
	"net/http"
	"testing"
	"time"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

// auditReport is what a scan of every check returns: one control passes and
// one critical control fails.
func auditReport(host store.Host, selected []string, _ scan.Options) (map[string]any, error) {
	results := map[string]any{}
	for _, id := range selected {
		if id == checks.Packages {
			continue
		}
		results[id] = checks.Result{Status: checks.StatusCompleted, Summary: "No issues found", Findings: []checks.Finding{}}
	}
	results[checks.Hardening] = checks.Result{Status: checks.StatusCompleted, Privileged: true, Controls: []checks.ControlResult{
		{ID: "SSH-01", Category: "SSH", Severity: "high", Status: checks.ControlPass, Title: "Root cannot log in"},
		{ID: "ACC-02", Category: "Accounts and passwords", Severity: "critical", Status: checks.ControlFail, Title: "No empty passwords", Evidence: "guest"},
	}, Inventory: &checks.Inventory{Hostname: "ip-10-92-0-52", OS: "Ubuntu 24.04 LTS",
		Listening: []checks.Listening{{Protocol: "tcp", Address: "0.0.0.0", Port: 3306, Exposed: true}}},
		Facts: &checks.Facts{SSHD: map[string]string{"permitrootlogin": "no"}, LoginDefs: map[string]string{"pass_max_days": "60"},
			Packages: []string{"openssh-server"}, Active: []string{"node_exporter"}}}
	return map[string]any{"host_id": host.ID, "address": host.Address, "os": "Ubuntu 24.04 LTS", "findings": []any{}, "check_results": results}, nil
}

func TestAuditIsGradedAndRisksCanBeAccepted(t *testing.T) {
	s := newTestServer(t, auditReport)
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	started := request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/audits", map[string]any{"advanced": true})
	record := decode[store.Scan](t, started)
	if started.Code != http.StatusAccepted || !record.Audit {
		t.Fatalf("start audit: %d %s", started.Code, started.Body.String())
	}
	s.runner.wait()
	detail := decode[auditDetail](t, request(t, s, http.MethodGet, "/api/audits/"+record.ID, nil))
	if detail.Summary == nil || detail.Scan.Checks[len(detail.Scan.Checks)-1] != checks.YARA {
		t.Fatalf("audit = %+v", detail)
	}
	// 6 of 16 points, and a failed critical control: an F.
	if detail.Summary.Grade != "F" || detail.Summary.Score != 38 || detail.Summary.Counts.Failed != 1 || detail.Summary.Inventory.Hostname != "ip-10-92-0-52" {
		t.Fatalf("summary = %+v", detail.Summary)
	}

	if bad := request(t, s, http.MethodPost, "/api/exceptions", map[string]any{"host_id": host.ID, "control_id": "NOPE-1", "reason": "x"}); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown control: %d", bad.Code)
	}
	if bad := request(t, s, http.MethodPost, "/api/exceptions", map[string]any{"host_id": host.ID, "control_id": "ACC-02"}); bad.Code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", bad.Code)
	}
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	created := request(t, s, http.MethodPost, "/api/exceptions", map[string]any{"host_id": host.ID, "control_id": "ACC-02", "reason": "Guest kiosk account, no network login", "expires_at": expires})
	exception := decode[store.Exception](t, created)
	if created.Code != http.StatusCreated {
		t.Fatalf("accept: %d %s", created.Code, created.Body.String())
	}
	detail = decode[auditDetail](t, request(t, s, http.MethodGet, "/api/audits/"+record.ID, nil))
	if detail.Summary.Grade != "A" || detail.Summary.Counts.Accepted != 1 || detail.Summary.Controls[1].Status != audit.Accepted {
		t.Fatalf("after accepting: %+v", detail.Summary)
	}
	list := decode[[]auditListItem](t, request(t, s, http.MethodGet, "/api/audits?host_id="+host.ID, nil))
	if len(list) != 1 || list[0].Grade != "A" {
		t.Fatalf("list = %+v", list)
	}
	if removed := request(t, s, http.MethodDelete, "/api/exceptions/"+exception.ID, nil); removed.Code != http.StatusNoContent {
		t.Fatalf("remove: %d", removed.Code)
	}
	if detail = decode[auditDetail](t, request(t, s, http.MethodGet, "/api/audits/"+record.ID, nil)); detail.Summary.Grade != "F" {
		t.Fatalf("after removing the exception: %s", detail.Summary.Grade)
	}

	// An ordinary scan is not an audit, and audits survive pruning.
	plain := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+host.ID+"/scans", map[string]any{}))
	s.runner.wait()
	if missing := request(t, s, http.MethodGet, "/api/audits/"+plain.ID, nil); missing.Code != http.StatusNotFound {
		t.Fatalf("a plain scan as an audit: %d", missing.Code)
	}
	if _, err := store.PruneScans(host.ID, 0); err != nil {
		t.Fatal(err)
	}
	if kept := request(t, s, http.MethodGet, "/api/audits/"+record.ID, nil); kept.Code != http.StatusOK {
		t.Fatalf("audit after pruning: %d", kept.Code)
	}
}

func TestAuditOnEnrollSetting(t *testing.T) {
	s := newTestServer(t, auditReport)
	if on := decode[auditSettings](t, request(t, s, http.MethodGet, "/api/settings/audit", nil)); on.AuditOnEnroll {
		t.Fatal("on by default")
	}
	if saved := request(t, s, http.MethodPatch, "/api/settings/audit", map[string]bool{"audit_on_enroll": true}); saved.Code != http.StatusOK {
		t.Fatalf("save: %d", saved.Code)
	}
	if on, _ := store.AuditOnEnroll(); !on {
		t.Fatal("not saved")
	}
}
