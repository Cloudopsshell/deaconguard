package store

import (
	"testing"
	"time"
)

func TestFixDeadlines(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "web-01", TransportLocal)
	db, err := database()
	if err != nil {
		t.Fatal(err)
	}
	scanWith := func(findings ...any) string {
		scan, err := CreateScan(host, []string{CheckPackages})
		if err != nil {
			t.Fatal(err)
		}
		if err := CompleteScan(scan.ID, map[string]any{"host_id": host.ID, "findings": findings}); err != nil {
			t.Fatal(err)
		}
		return scan.ID
	}
	finding := func(cve, severity, fix, priority string) map[string]any {
		return map[string]any{"id": cve, "package": "p", "installed_version": "1", "fixed_version": "2", "severity": severity, "fix": fix,
			"priority": priority, "exploit": map[string]any{"kev": priority == "exploited"}}
	}
	scanWith(finding("CVE-1", "HIGH", "available", "severe"), finding("CVE-2", "LOW", "available", "exploited"), finding("CVE-3", "CRITICAL", "none", "severe"))
	// Pretend the first scan was 40 days ago.
	past := time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := db.Exec("UPDATE host_cve_seen SET first_seen = ?, last_seen = ?", past, past); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE scans SET started_at = ?, finished_at = ?", past, past); err != nil {
		t.Fatal(err)
	}
	scanWith(finding("CVE-1", "HIGH", "available", "severe"), finding("CVE-2", "LOW", "available", "exploited"), finding("CVE-3", "CRITICAL", "none", "severe"))
	findings, err := LatestFindings()
	if err != nil {
		t.Fatal(err)
	}
	byCVE := map[string]LatestFinding{}
	for _, item := range findings {
		byCVE[item.CVE] = item
	}
	// High: 30 days, past. Low but known exploited: 14 days, past. Critical
	// with no fix: past its date, but not overdue, since nothing can be done.
	if !byCVE["CVE-1"].Overdue || !byCVE["CVE-2"].Overdue || byCVE["CVE-3"].Overdue || byCVE["CVE-3"].DueAt == "" {
		t.Fatalf("overdue: %+v", byCVE)
	}
	if byCVE["CVE-1"].FirstSeen != past {
		t.Fatalf("first seen: %s", byCVE["CVE-1"].FirstSeen)
	}
	due, _ := time.Parse(time.RFC3339, byCVE["CVE-2"].DueAt)
	if first, _ := time.Parse(time.RFC3339, past); due.Sub(first) != 14*24*time.Hour {
		t.Fatalf("a known exploited vulnerability gets the shorter deadline: %v", due.Sub(first))
	}

	// Fixed, then back: the deadline starts again.
	scanWith(finding("CVE-2", "LOW", "available", "exploited"))
	scanWith(finding("CVE-1", "HIGH", "available", "severe"), finding("CVE-2", "LOW", "available", "exploited"))
	findings, _ = LatestFindings()
	for _, item := range findings {
		if item.CVE == "CVE-1" && (item.Overdue || item.FirstSeen == past) {
			t.Fatalf("a returning vulnerability kept its old date: %+v", item)
		}
		if item.CVE == "CVE-2" && item.FirstSeen != past {
			t.Fatalf("a vulnerability present all along lost its date: %+v", item)
		}
	}

	// Turned off, nothing is due.
	off := DefaultSLA
	off.Enabled = false
	if err := SetSLA(off); err != nil {
		t.Fatal(err)
	}
	findings, _ = LatestFindings()
	for _, item := range findings {
		if item.DueAt != "" || item.Overdue {
			t.Fatalf("deadlines are off: %+v", item)
		}
	}
	if SetSLA(SLA{Enabled: true, Exploited: 0, Critical: 1, High: 1, Medium: 1, Low: 1}) == nil {
		t.Fatal("a 0-day deadline was accepted")
	}
}

func TestMaintenanceWindows(t *testing.T) {
	withTempDataDir(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	at := func(hours int) string { return now.Add(time.Duration(hours) * time.Hour).Format(time.RFC3339) }
	for name, bad := range map[string]MaintenanceWindow{
		"no name":   {StartsAt: at(-1), EndsAt: at(1)},
		"backwards": {Name: "x", StartsAt: at(1), EndsAt: at(-1)},
		"too long":  {Name: "x", StartsAt: at(0), EndsAt: at(24 * 8)},
		"over":      {Name: "x", StartsAt: at(-3), EndsAt: at(-2)},
		"bad tag":   {Name: "x", StartsAt: at(0), EndsAt: at(1), Tags: []string{"no spaces"}},
	} {
		if _, err := AddMaintenanceWindow(bad, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	window, err := AddMaintenanceWindow(MaintenanceWindow{Name: "Patch Tuesday", StartsAt: at(-1), EndsAt: at(2), Tags: []string{"Prod"}, SkipScans: true}, now)
	if err != nil || window.Status != "active" || window.Tags[0] != "prod" {
		t.Fatalf("%+v %v", window, err)
	}
	if _, err := AddMaintenanceWindow(MaintenanceWindow{Name: "later", StartsAt: at(5), EndsAt: at(6)}, now); err != nil {
		t.Fatal(err)
	}
	if found, in, _ := InMaintenance([]string{"prod", "web"}, now); !in || found.Name != "Patch Tuesday" {
		t.Fatal("a prod host is in the window")
	}
	if _, in, _ := InMaintenance([]string{"staging"}, now); in {
		t.Fatal("a staging host is not")
	}
	if _, in, _ := InMaintenance(nil, now.Add(5*time.Hour+time.Minute)); !in {
		t.Fatal("a window without tags covers every host")
	}
	if _, in, _ := InMaintenance([]string{"prod"}, now.Add(3*time.Hour)); in {
		t.Fatal("an ended window still applied")
	}
	if _, err := DeleteMaintenanceWindow(window.ID); err != nil {
		t.Fatal(err)
	}
	if _, in, _ := InMaintenance([]string{"prod"}, now); in {
		t.Fatal("a deleted window still applied")
	}
}
