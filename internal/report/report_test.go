package report

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
	"deaconguard/internal/lifecycle"
	"deaconguard/internal/store"
)

// sample is an audit of a machine with a bit of everything, including
// evidence that tries to be HTML and a spreadsheet formula.
func sample(t *testing.T) Report {
	t.Helper()
	controls := []checks.ControlResult{
		{ID: "ACC-02", Category: "Accounts and passwords", Title: "No account has an empty password", Severity: "critical", Status: checks.ControlFail,
			Evidence: "accounts with an empty password: <script>alert(1)</script>", Rationale: "Anyone can log in.", Remediation: "passwd -l NAME."},
		{ID: "SSH-01", Category: "SSH", Title: "Root cannot log in over SSH with a password", Severity: "high", Status: checks.ControlPass, Evidence: "permitrootlogin no"},
		{ID: "SSH-02", Category: "SSH", Title: "SSH password logins are off", Severity: "medium", Status: checks.ControlFail, Evidence: "=HYPERLINK(\"x\")",
			Rationale: "Passwords can be guessed.", Remediation: "PasswordAuthentication no."},
		{ID: "NET-01", Category: "Network", Title: "IP forwarding is off", Severity: "medium", Status: checks.ControlNA, Evidence: "runs containers"},
	}
	scan := store.Scan{ID: "scan1", HostID: "host1", Address: "ip-10-92-0-52", OS: "Ubuntu 24.04 LTS", StartedAt: "2026-10-12T09:00:00Z",
		Checks: audit.Checks, Fixes: &store.FixSummary{Counts: map[string]int{"available": 2, "none": 1}, Actionable: store.SeverityCounts{High: 1, Medium: 1}},
		Exploit:   store.ExploitCounts{Known: 2, KnownFixable: 1, Data: true},
		Lifecycle: &lifecycle.Lifecycle{State: lifecycle.Supported, Until: "2029-04", Note: "Security fixes until April 2029"}}
	epss := 0.42
	raw := map[string]any{
		"findings": []any{
			map[string]any{"id": "CVE-2026-0002", "package": "zlib1g", "installed_version": "1:1.3", "fixed_version": "", "severity": "low", "fix": "none",
				"priority": "exploited", "exploit": map[string]any{"kev": true, "kev_due": "2026-11-01"}},
			map[string]any{"id": "CVE-2026-0001", "package": "openssl", "installed_version": "3.0.13", "fixed_version": "3.0.14", "severity": "HIGH", "fix": "available",
				"priority": "severe", "cvss_score": 7.5, "exploit": map[string]any{"kev": false, "epss": &epss}},
			map[string]any{"id": "CVE-2026-0003", "package": "sudo", "installed_version": "1.9.15", "fixed_version": "1.9.16", "severity": "MEDIUM", "fix": "available",
				"priority": "exploited", "cvss_score": 8.8, "exploit": map[string]any{"kev": true, "kev_due": "2026-10-30", "ransomware": true}},
		},
		"exploit_data": map[string]any{"kev": map[string]any{"available": true, "version": "2026.10.08"}, "epss": map[string]any{"available": true, "version": "2026-10-12"}},
		"check_results": map[string]any{
			checks.Hardening: checks.Result{Status: "completed", Controls: controls, Inventory: &checks.Inventory{Hostname: "ip-10-92-0-52", OS: "Ubuntu 24.04 LTS",
				Kernel: "Linux 6.8.0", Architecture: "x86_64", CPUs: 2, MemoryBytes: 4 << 30, Disks: []checks.Disk{{Mount: "/", SizeBytes: 40 << 30, UsedBytes: 12 << 30, UsedPercent: 30}},
				Listening: []checks.Listening{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Exposed: true}}}},
			checks.Config: checks.Result{Status: "completed", Summary: "1 issue found", Findings: []checks.Finding{{Severity: "LOW", Title: "No host firewall", Evidence: "@SUM(1)"}}},
		},
	}
	exceptions := []store.Exception{{ControlID: "SSH-02", HostID: "host1", Reason: "Client's backup tool needs it", CreatedBy: "admin", CreatedAt: "2026-10-12T09:30:00Z"}}
	summary, err := audit.Grade(scan, raw, exceptions, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	built, err := Build(Source{ID: "0123456789abcdef0123456789abcdef", Scan: scan, Host: store.Host{ID: "host1", Address: "ip-10-92-0-52"}, Report: raw,
		Summary: &summary, Branding: Branding{Company: "CloudOpsShell Ltd", Contact: "security@example.com · +44 20 0000 0000"},
		Client: "Acme Corp", Notes: "Handover of the new web server.", By: "admin", Now: time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC), Version: "0.13.0"})
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func TestReportBuildsInEveryFormat(t *testing.T) {
	report := sample(t)
	if report.Kind != "audit" || report.Audit.Counts.Accepted != 1 {
		t.Fatalf("report = %+v", report)
	}
	// Fixable first; among them, known exploited first, whatever the severity.
	if order := report.Vulnerabilities[0].ID + " " + report.Vulnerabilities[1].ID + " " + report.Vulnerabilities[2].ID; order != "CVE-2026-0003 CVE-2026-0001 CVE-2026-0002" {
		t.Fatalf("order: %s", order)
	}
	if e := report.Exploit; e == nil || e.Known != 2 || e.KnownFixable != 1 || e.KEVVersion != "2026.10.08" || e.EPSSDate != "2026-10-12" {
		t.Fatalf("exploit: %+v", report.Exploit)
	}
	if first := report.Vulnerabilities[0]; first.Exploitation() != "Known exploited, ransomware" || first.CVSS() != "8.8" ||
		report.Vulnerabilities[1].Exploitation() != "EPSS 42%" || Percent(0.003) != "0.3%" || Percent(0.99957) != "99.9%" || Percent(1) != "100.0%" {
		t.Fatalf("labels: %q %q %q", first.Exploitation(), first.CVSS(), report.Vulnerabilities[1].Exploitation())
	}
	if view := newView(report, ""); len(view.Waiting) != 1 || view.Waiting[0].Exploited != 1 {
		t.Fatalf("waiting: %+v", view.Waiting)
	}
	snapshot, fingerprint, err := Snapshot(report)
	if err != nil || len(fingerprint) != 64 {
		t.Fatal(err)
	}
	if _, again, _ := Snapshot(report); again != fingerprint {
		t.Fatal("the fingerprint is not stable")
	}
	_ = snapshot

	page, err := HTML(report, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("<script>alert")) || !bytes.Contains(page, []byte("Acme Corp")) || !bytes.Contains(page, []byte(FormatFingerprint(fingerprint))) ||
		!bytes.Contains(page, []byte("Known exploited, ransomware")) || !bytes.Contains(page, []byte("2 known to be exploited (CISA KEV)")) ||
		!bytes.Contains(page, []byte("Supported: Security fixes until April 2029")) {
		t.Fatal("the HTML report is not escaped, or misses its client or fingerprint")
	}

	table, err := CSV(report)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(table)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		for _, cell := range record {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Fatalf("a cell could run as a formula: %q", cell)
			}
		}
	}
	if len(records) != 1+4+3+1 {
		t.Fatalf("%d CSV rows", len(records))
	}
	if records[5][1] != "CVE-2026-0003" || records[5][7] != "8.8" || records[5][9] != "yes, due 2026-10-30, used in ransomware" || records[6][8] != "0.4200" {
		t.Fatalf("exploit columns: %q %q", records[5], records[6])
	}

	document, err := PDF(report, fingerprint)
	if err != nil || !bytes.HasPrefix(document, []byte("%PDF-")) {
		t.Fatalf("PDF: %v", err)
	}
	workbook, err := XLSX(report, fingerprint)
	if err != nil || !bytes.HasPrefix(workbook, []byte("PK")) {
		t.Fatalf("XLSX: %v", err)
	}
	if encoded, err := JSON(report, fingerprint); err != nil || !bytes.Contains(encoded, []byte(fingerprint)) {
		t.Fatalf("JSON: %v", err)
	}

	// For looking at: DEACONGUARD_REPORT_SAMPLES=dir go test ./internal/report
	if directory := os.Getenv("DEACONGUARD_REPORT_SAMPLES"); directory != "" {
		for name, contents := range map[string][]byte{"report.pdf": document, "report.html": page, "report.csv": table, "report.xlsx": workbook} {
			if err := os.WriteFile(filepath.Join(directory, name), contents, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestScanReportsHaveNoGrade(t *testing.T) {
	report, err := Build(Source{ID: "0123456789abcdef0123456789abcdef", Scan: store.Scan{ID: "s", Checks: []string{checks.Packages}, Fixes: &store.FixSummary{}},
		Host: store.Host{Address: "web-01"}, Report: map[string]any{"findings": []any{}}, Now: time.Now()})
	if err != nil || report.Kind != "scan" || report.Audit != nil {
		t.Fatalf("report = %+v, %v", report, err)
	}
	if _, err := PDF(report, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := HTML(report, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
}
