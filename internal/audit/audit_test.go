package audit

import (
	"testing"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/store"
)

func report(controls []checks.ControlResult, others map[string]checks.Result) map[string]any {
	results := map[string]any{checks.Hardening: checks.Result{Status: checks.StatusCompleted, Controls: controls}}
	for id, result := range others {
		results[id] = result
	}
	return map[string]any{"check_results": results}
}

func control(id, severity, status string) checks.ControlResult {
	return checks.ControlResult{ID: id, Category: "SSH", Severity: severity, Status: status}
}

func TestGradeWeighsControlsBySeverity(t *testing.T) {
	scan := store.Scan{HostID: "h1", Checks: Checks, Fixes: &store.FixSummary{}}
	controls := []checks.ControlResult{control("A", "high", "pass"), control("B", "low", "fail"), control("C", "medium", "na")}
	summary, err := Grade(scan, report(controls, nil), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 6 of 7 weighted points pass: 86, a B.
	if summary.Score != 86 || summary.Grade != "B" || summary.Counts.Passed != 1 || summary.Counts.Failed != 1 || summary.Counts.NotApplicable != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestBlockersCapTheGrade(t *testing.T) {
	controls := []checks.ControlResult{control("A", "high", "pass")}
	cases := []struct {
		name   string
		scan   store.Scan
		others map[string]checks.Result
		grade  string
	}{
		{"high fix available", store.Scan{Fixes: &store.FixSummary{Actionable: store.SeverityCounts{High: 2}}}, nil, "B"},
		{"critical fix available", store.Scan{Fixes: &store.FixSummary{Actionable: store.SeverityCounts{Critical: 1, High: 3}}}, nil, "C"},
		{"known exploited fix available", store.Scan{Fixes: &store.FixSummary{Actionable: store.SeverityCounts{High: 1}}, Exploit: store.ExploitCounts{Known: 2, KnownFixable: 1, Data: true}}, nil, "D"},
		{"changed system files", store.Scan{Fixes: &store.FixSummary{}}, map[string]checks.Result{checks.Integrity: {Findings: []checks.Finding{{Severity: "HIGH"}}}}, "D"},
		{"malware", store.Scan{Fixes: &store.FixSummary{}}, map[string]checks.Result{checks.Antivirus: {Findings: []checks.Finding{{Severity: "CRITICAL"}}}}, "F"},
	}
	for _, c := range cases {
		c.scan.Checks = Checks
		summary, err := Grade(c.scan, report(controls, c.others), nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if summary.Score != 100 || summary.Grade != c.grade || len(summary.Caps) == 0 {
			t.Errorf("%s: grade %s score %d caps %v", c.name, summary.Grade, summary.Score, summary.Caps)
		}
	}
}

func TestAcceptedRisksLeaveTheScore(t *testing.T) {
	scan := store.Scan{HostID: "h1", Checks: Checks, Fixes: &store.FixSummary{}}
	controls := []checks.ControlResult{control("A", "high", "pass"), control("B", "critical", "fail"), control("C", "critical", "fail")}
	now := time.Now()
	exceptions := []store.Exception{
		{ControlID: "B", HostID: "h1", Reason: "bastion host"},
		// For another host, and expired: neither applies.
		{ControlID: "C", HostID: "h2", Reason: "other"},
		{ControlID: "C", HostID: "", Reason: "old", ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)},
	}
	summary, err := Grade(scan, report(controls, nil), exceptions, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Counts.Accepted != 1 || summary.Counts.Failed != 1 || summary.Controls[1].Status != Accepted || summary.Controls[1].Exception == nil {
		t.Fatalf("counts %+v, B = %+v", summary.Counts, summary.Controls[1])
	}
	// 6 of 16 points pass, and a critical control still fails.
	if summary.Score != 38 || summary.Grade != "F" {
		t.Fatalf("score %d grade %s", summary.Score, summary.Grade)
	}
}

func TestIncompleteAuditsSayWhy(t *testing.T) {
	scan := store.Scan{Checks: []string{checks.Hardening, checks.Antivirus}}
	controls := []checks.ControlResult{control("A", "high", "unknown")}
	summary, err := Grade(scan, report(controls, map[string]checks.Result{checks.Antivirus: {Status: checks.StatusSkipped, Summary: "ClamAV is not installed"}}), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Incomplete) != 3 {
		t.Fatalf("incomplete = %v", summary.Incomplete)
	}
}
