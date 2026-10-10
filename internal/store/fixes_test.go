package store

import (
	"testing"
)

func TestReportsAreSummedByFixState(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "web-01.example", TransportLocal)
	record, err := CreateScan(host, []string{CheckPackages})
	if err != nil {
		t.Fatal(err)
	}
	if err := CompleteScan(record.ID, map[string]any{
		"os": "Ubuntu 24.04 LTS", "checks_run": []string{CheckPackages},
		"findings": []map[string]any{
			{"id": "CVE-1", "package": "openssl", "fixed_version": "3.1", "fix": "available", "severity": "HIGH", "cvss_severity": "CRITICAL"},
			{"id": "CVE-2", "package": "running kernel", "fixed_version": "0:6.8.0-35", "fix": "reboot", "severity": "MEDIUM"},
			{"id": "CVE-3", "package": "python3.12", "fix": "none", "severity": "CRITICAL"},
			{"id": "CVE-4", "package": "libxmltok1t64", "fixed_version": "1.2+esm3", "fix": "ubuntu_pro", "severity": "LOW"},
			// A report from before 0.7.0: no fix state.
			{"id": "CVE-5", "package": "curl", "fixed_version": "8.5", "severity": "LOW"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	scan, err := GetScan(record.ID)
	if err != nil || scan.Fixes == nil {
		t.Fatalf("GetScan() = %+v, %v", scan, err)
	}
	want := map[string]int{"available": 2, "reboot": 1, "old_kernel": 0, "ubuntu_pro": 1, "none": 1}
	for state, count := range want {
		if scan.Fixes.Counts[state] != count {
			t.Errorf("%s = %d, want %d", state, scan.Fixes.Counts[state], count)
		}
	}
	if actionable := scan.Fixes.Actionable; actionable.Critical != 0 || actionable.High != 1 || actionable.Medium != 1 || actionable.Low != 1 {
		t.Errorf("actionable = %+v", actionable)
	}
	affected, err := VulnerabilityHosts("CVE-5")
	if err != nil || len(affected) != 1 || affected[0].Fix != "available" {
		t.Fatalf("VulnerabilityHosts() = %+v, %v", affected, err)
	}
	vulnerabilities, _ := Vulnerabilities()
	for _, vulnerability := range vulnerabilities {
		if fixable := vulnerability.FixableHosts; (vulnerability.CVE == "CVE-3" || vulnerability.CVE == "CVE-4") != (fixable == 0) {
			t.Errorf("%s fixable on %d hosts", vulnerability.CVE, fixable)
		}
	}
}

func TestOlderFindingsAreBackfilled(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "web-01.example", TransportLocal)
	record, err := CreateScan(host, []string{CheckPackages})
	if err != nil {
		t.Fatal(err)
	}
	if err := CompleteScan(record.ID, map[string]any{"checks_run": []string{CheckPackages}, "findings": []map[string]any{
		{"id": "CVE-1", "package": "openssl", "fixed_version": "3.1", "severity": "HIGH"},
		{"id": "CVE-2", "package": "python3.12", "severity": "CRITICAL"},
	}}); err != nil {
		t.Fatal(err)
	}
	db, err := database()
	if err != nil {
		t.Fatal(err)
	}
	// What a database from 0.6.0 holds after the columns are added.
	if _, err := db.Exec(`UPDATE findings SET fix = ''; UPDATE scans SET fix_summary = ''; UPDATE scan_checks SET fix_summary = ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(backfillV8); err != nil {
		t.Fatal(err)
	}
	scan, err := GetScan(record.ID)
	if err != nil || scan.Fixes == nil || scan.Fixes.Counts["available"] != 1 || scan.Fixes.Counts["none"] != 1 || scan.Fixes.Actionable.High != 1 || scan.Fixes.Actionable.Critical != 0 {
		t.Fatalf("backfilled scan = %+v, %v", scan.Fixes, err)
	}
	checks, err := latestChecks(db, host.ID)
	if err != nil || checks[CheckPackages].Fixes == nil || checks[CheckPackages].Fixes.Counts["none"] != 1 {
		t.Fatalf("backfilled check = %+v, %v", checks[CheckPackages], err)
	}
}
