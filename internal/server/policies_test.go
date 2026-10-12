package server

import (
	"net/http"
	"strings"
	"testing"

	"deaconguard/internal/compliance"
	"deaconguard/internal/policy"
	"deaconguard/internal/store"
)

func TestPoliciesAndComplianceShowOnAuditsAndReports(t *testing.T) {
	s := newTestServer(t, auditReport)
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	if bad := request(t, s, http.MethodPost, "/api/policies", map[string]string{"source": "name: x\ncontrols: []"}); bad.Code != http.StatusBadRequest ||
		!strings.Contains(bad.Body.String(), "1 to 200 controls") {
		t.Fatalf("bad policy: %d %s", bad.Code, bad.Body.String())
	}
	created := request(t, s, http.MethodPost, "/api/policies", map[string]string{"source": policy.Example})
	added := decode[policyResponse](t, created)
	if created.Code != http.StatusCreated || added.Name != "Acme server policy" || added.Controls != 5 || !added.Enabled {
		t.Fatalf("add: %d %s", created.Code, created.Body.String())
	}

	audited := finishedAudit(t, s, host.ID)
	detail := decode[auditDetail](t, request(t, s, http.MethodGet, "/api/audits/"+audited.ID, nil))
	if len(detail.Summary.Policies) != 1 {
		t.Fatalf("policies = %+v", detail.Summary.Policies)
	}
	result := detail.Summary.Policies[0]
	// ACME-01 passes (PermitRootLogin no); ACME-05 fails (MySQL on every interface).
	if result.Counts.Passed != 4 || result.Counts.Failed != 1 {
		t.Fatalf("policy counts = %+v", result.Counts)
	}
	if len(detail.Compliance) != len(compliance.Frameworks()) {
		t.Fatalf("%d compliance views", len(detail.Compliance))
	}

	// A failed policy control's risk can be accepted like a baseline one.
	if accepted := request(t, s, http.MethodPost, "/api/exceptions", map[string]any{"host_id": host.ID, "control_id": "ACME-05", "reason": "behind a private subnet"}); accepted.Code != http.StatusCreated {
		t.Fatalf("accept policy control: %d %s", accepted.Code, accepted.Body.String())
	}
	detail = decode[auditDetail](t, request(t, s, http.MethodGet, "/api/audits/"+audited.ID, nil))
	if detail.Summary.Policies[0].Counts.Accepted != 1 {
		t.Fatalf("after accepting: %+v", detail.Summary.Policies[0].Counts)
	}

	if bad := request(t, s, http.MethodPost, "/api/reports", map[string]any{"scan_id": audited.ID, "frameworks": []string{"sox"}}); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown framework: %d", bad.Code)
	}
	record := decode[store.ReportRecord](t, request(t, s, http.MethodPost, "/api/reports", map[string]any{"scan_id": audited.ID, "frameworks": []string{compliance.PCI, compliance.ISO}}))
	_, built, err := loadReport(record.ID)
	if err != nil || len(built.Compliance) != 2 || built.Compliance[0].Framework.ID != compliance.PCI || len(built.Policies) != 1 {
		t.Fatalf("report compliance = %d, policies = %d, %v", len(built.Compliance), len(built.Policies), err)
	}
	for _, format := range []string{"pdf", "html", "csv", "xlsx"} {
		download := request(t, s, http.MethodGet, "/api/reports/"+record.ID+"/download?format="+format, nil)
		if download.Code != http.StatusOK {
			t.Fatalf("%s: %d", format, download.Code)
		}
		if format == "html" && (!strings.Contains(download.Body.String(), "PCI DSS v4.0") || !strings.Contains(download.Body.String(), "Policy: Acme server policy")) {
			t.Fatal("the HTML report lacks the compliance mapping or the policy")
		}
	}

	// A policy turned off no longer counts.
	request(t, s, http.MethodPatch, "/api/policies/"+added.ID, map[string]bool{"enabled": false})
	if detail = decode[auditDetail](t, request(t, s, http.MethodGet, "/api/audits/"+audited.ID, nil)); len(detail.Summary.Policies) != 0 {
		t.Fatal("a disabled policy still counts")
	}
	if deleted := request(t, s, http.MethodDelete, "/api/policies/"+added.ID, nil); deleted.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", deleted.Code)
	}
}
