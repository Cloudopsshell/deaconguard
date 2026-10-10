package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"deaconguard/internal/runstate"
)

func TestScanLifecycleAndVulnerabilityQueries(t *testing.T) {
	withTempDataDir(t)
	first := addTestHost(t, "a.example", TransportLocal)
	second := addTestHost(t, "b.example", TransportLocal)
	finding := func(cve, pkg, severity string) map[string]any {
		return map[string]any{"id": cve, "package": pkg, "installed_version": "1", "fixed_version": "2", "severity": severity}
	}
	for _, host := range []Host{first, second} {
		scan, err := CreateScan(host, []string{CheckPackages})
		if err != nil || scan.Status != ScanRunning {
			t.Fatalf("CreateScan() = %+v, %v", scan, err)
		}
		err = CompleteScan(scan.ID, map[string]any{
			"host_id": host.ID, "address": host.Address, "os": "Ubuntu 24.04 LTS",
			"findings":         []any{finding("CVE-2026-1", "openssl", "HIGH"), finding("CVE-2026-2", "zlib", "LOW")},
			"unsupported_cves": []any{map[string]any{"id": "CVE-2026-9"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	failed, err := CreateScan(first, []string{CheckPackages})
	if err != nil {
		t.Fatal(err)
	}
	if err := WaitForInput(failed.ID, ScanNeedsSudo, "Wrong password"); err != nil {
		t.Fatal(err)
	}
	if waiting, err := GetScan(failed.ID); err != nil || waiting.Error != "Wrong password" || waiting.FinishedAt != nil {
		t.Fatalf("waiting scan = %+v, %v", waiting, err)
	}
	if _, err := GetReport(failed.ID); err == nil {
		t.Fatal("a failed scan must not produce a report")
	}

	summaries, err := HostSummaries()
	if err != nil || len(summaries) != 2 {
		t.Fatalf("HostSummaries() = %+v, %v", summaries, err)
	}
	if summaries[0].LastScan.Status != ScanNeedsSudo || summaries[0].LastReport.Status != ScanSucceeded {
		t.Fatalf("latest scan should be the failure while the report stays the last success: %+v", summaries[0])
	}
	if summaries[0].LastReport.UnsupportedCount != 1 {
		t.Fatalf("unsupported rules were not counted: %+v", summaries[0].LastReport)
	}

	vulnerabilities, err := Vulnerabilities()
	if err != nil || len(vulnerabilities) != 2 {
		t.Fatalf("Vulnerabilities() = %+v, %v", vulnerabilities, err)
	}
	if vulnerabilities[0].CVE != "CVE-2026-1" || vulnerabilities[0].HostCount != 2 {
		t.Fatalf("highest severity CVE should sort first across both hosts: %+v", vulnerabilities[0])
	}
	affected, err := VulnerabilityHosts("CVE-2026-2")
	if err != nil || len(affected) != 2 || affected[0].Address != "a.example" {
		t.Fatalf("VulnerabilityHosts() = %+v, %v", affected, err)
	}

	if err := InterruptRunningScans(&runstate.Stop{Message: "The machine restarted."}); err != nil {
		t.Fatal(err)
	}
	if interrupted, err := GetScan(failed.ID); err != nil || interrupted.Status != ScanFailed || interrupted.FinishedAt == nil ||
		interrupted.Error != "The DeaconGuard server stopped while this scan was running. The machine restarted. Run the scan again." {
		t.Fatalf("a scan waiting for input when the server stopped must be failed: %+v, %v", interrupted, err)
	}
	if err := CompleteScan(failed.ID, map[string]any{}); err == nil {
		t.Fatal("completing a scan that is no longer running should fail")
	}
}

func TestCheckResultsAreSummarizedPerCheck(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "c.example", TransportLocal)
	host, err := SetAllowSudo(host.ID, true)
	if err != nil || !host.AllowSudo {
		t.Fatalf("SetAllowSudo() = %+v, %v", host, err)
	}
	full, err := CreateScan(host, []string{CheckPackages, "integrity"})
	if err != nil {
		t.Fatal(err)
	}
	err = CompleteScan(full.ID, map[string]any{
		"host_id": host.ID, "checks_run": []any{CheckPackages, "integrity"},
		"findings": []any{map[string]any{"id": "CVE-2026-1", "package": "bash", "severity": "HIGH"}},
		"check_results": map[string]any{"integrity": map[string]any{
			"status": "partial", "privileged": false, "summary": "1 modified file", "notes": []any{"12 files unreadable"},
			"findings": []any{map[string]any{"rule": "integrity.modified-binary", "severity": "HIGH", "title": "Modified", "evidence": "/usr/bin/ls"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A later scan that skipped packages must not replace the package results.
	configOnly, err := CreateScan(host, []string{"config"})
	if err != nil {
		t.Fatal(err)
	}
	if err := CompleteScan(configOnly.ID, map[string]any{
		"host_id": host.ID, "checks_run": []any{"config"},
		"check_results": map[string]any{"config": map[string]any{"status": "completed", "findings": []any{}}},
	}); err != nil {
		t.Fatal(err)
	}
	summaries, err := HostSummaries()
	if err != nil || len(summaries) != 1 {
		t.Fatalf("HostSummaries() = %+v, %v", summaries, err)
	}
	summary := summaries[0]
	if summary.LastScan.ID != configOnly.ID || summary.LastReport == nil || summary.LastReport.ID != full.ID {
		t.Fatalf("package results should come from the last scan that checked packages: %+v", summary)
	}
	integrity := summary.Checks["integrity"]
	if integrity.ScanID != full.ID || integrity.Status != "partial" || integrity.Severity.High != 1 {
		t.Fatalf("integrity summary = %+v", integrity)
	}
	if summary.Checks[CheckPackages].Severity.High != 1 || summary.Checks["config"].ScanID != configOnly.ID {
		t.Fatalf("check summaries = %+v", summary.Checks)
	}
	if vulnerabilities, err := Vulnerabilities(); err != nil || len(vulnerabilities) != 1 {
		t.Fatalf("Vulnerabilities() = %+v, %v", vulnerabilities, err)
	}
}

func TestPruneKeepsNewestAndEachChecksLatestResult(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "prune.example", TransportLocal)
	complete := func(checks []string) Scan {
		scan, err := CreateScan(host, checks)
		if err != nil {
			t.Fatal(err)
		}
		report := map[string]any{"host_id": host.ID, "checks_run": checks}
		if checks[0] == CheckPackages {
			report["findings"] = []any{map[string]any{"id": "CVE-1", "package": "bash", "severity": "HIGH"}}
		} else {
			report["check_results"] = map[string]any{checks[0]: map[string]any{"status": "completed", "findings": []any{}}}
		}
		if err := CompleteScan(scan.ID, report); err != nil {
			t.Fatal(err)
		}
		return scan
	}
	packages := complete([]string{CheckPackages})
	for range 12 {
		complete([]string{"config"})
	}
	running, err := CreateScan(host, []string{"config"})
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteScan(running.ID); err != ErrScanInProgress {
		t.Fatalf("deleting a running scan: %v", err)
	}

	removed, err := PruneScans(host.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	// 14 scans: the running one and the 9 newest config scans make 10. Of the
	// 4 older ones, the package scan is protected as the only package result.
	if removed != 3 {
		t.Fatalf("removed %d scans, want 3", removed)
	}
	remaining, err := ListScans(host.ID, 100)
	if err != nil || len(remaining) != 11 {
		t.Fatalf("remaining = %d, %v", len(remaining), err)
	}
	if remaining[0].ID != running.ID || remaining[len(remaining)-1].ID != packages.ID {
		t.Fatalf("the running scan and the only package result must be kept: %+v", remaining)
	}
	summaries, err := HostSummaries()
	if err != nil || summaries[0].LastReport == nil || summaries[0].LastReport.ID != packages.ID {
		t.Fatalf("the vulnerabilities result was lost: %+v, %v", summaries, err)
	}

	if err := DeleteScan(packages.ID); err != nil {
		t.Fatal(err)
	}
	if summaries, _ := HostSummaries(); summaries[0].LastReport != nil {
		t.Fatalf("a deleted scan is still the latest report: %+v", summaries[0].LastReport)
	}
	if vulnerabilities, err := Vulnerabilities(); err != nil || len(vulnerabilities) != 0 {
		t.Fatalf("findings of a deleted scan remain: %+v, %v", vulnerabilities, err)
	}
}

func openOldDatabase(t *testing.T, statements string) {
	t.Helper()
	old, err := sql.Open("sqlite", "file:"+filepath.ToSlash(DatabasePath()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(statements)
	old.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Hosts in databases from before 0.1.0 were all registered for SSH scanning,
// which DeaconGuard removed; upgrading deletes them with their scans.
func TestVersionOneDatabaseIsUpgraded(t *testing.T) {
	withTempDataDir(t)
	openOldDatabase(t, schemaV1+`
		INSERT INTO meta (key, value) VALUES ('legacy_import', 'done');
		INSERT INTO hosts (id, address, username, port, created_at) VALUES ('h1', 'old.example', 'scanner', 22, '2026-01-01T00:00:00Z');
		INSERT INTO scans (id, host_id, address, status, started_at, finished_at, finding_count, high, report_json)
			VALUES ('s1', 'h1', 'old.example', 'succeeded', '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', 3, 3, '{}');`)
	if hosts, err := ListHosts(); err != nil || len(hosts) != 0 {
		t.Fatalf("SSH hosts survived the upgrade: %+v, %v", hosts, err)
	}
	if _, err := GetScan("s1"); err == nil {
		t.Fatal("the SSH host's scan survived the upgrade")
	}
	if host, err := AddLocalHost("build-01", "ops"); err != nil || host.Transport != TransportLocal {
		t.Fatalf("AddLocalHost after the upgrade = %+v, %v", host, err)
	}
}

func TestVersionFiveDatabaseLosesOnlySSHLeftovers(t *testing.T) {
	withTempDataDir(t)
	openOldDatabase(t, schemaV1+schemaV2+schemaV3+schemaV4+schemaV5+`
		INSERT INTO hosts (id, address, username, port, transport, created_at) VALUES
			('local', 'build-01', 'ops', 0, 'local', '2026-01-01T00:00:00Z'),
			('agent', 'web-03', 'root', 0, 'agent', '2026-01-01T00:00:00Z'),
			('ssh', 'old.example', 'ubuntu', 22, 'ssh', '2026-01-01T00:00:00Z');
		INSERT INTO scans (id, host_id, address, status, started_at, finished_at, report_json) VALUES
			('kept', 'local', 'build-01', 'succeeded', '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', '{}'),
			('gone', 'ssh', 'old.example', 'succeeded', '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', '{}');
		INSERT INTO scans (id, host_id, address, status, host_key_fingerprint, started_at) VALUES
			('paused', 'agent', 'web-03', 'needs_trust', 'SHA256:abc', '2026-01-01T00:00:00Z');`)
	hosts, err := ListHosts()
	if err != nil || len(hosts) != 2 || hosts[0].ID != "local" || hosts[1].ID != "agent" {
		t.Fatalf("hosts after the upgrade = %+v, %v", hosts, err)
	}
	if scan, err := GetScan("kept"); err != nil || scan.Status != ScanSucceeded {
		t.Fatalf("a local host's scan = %+v, %v", scan, err)
	}
	if _, err := GetScan("gone"); err == nil {
		t.Fatal("the SSH host's scan survived the upgrade")
	}
	if scan, err := GetScan("paused"); err != nil || scan.Status != ScanFailed || scan.FinishedAt == nil {
		t.Fatalf("a scan paused for an SSH prompt = %+v, %v", scan, err)
	}
	db, err := database()
	if err != nil {
		t.Fatal(err)
	}
	for table, column := range map[string]string{"hosts": "port", "scans": "host_key_fingerprint"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s.%s still exists: %d, %v", table, column, count, err)
		}
	}
}
