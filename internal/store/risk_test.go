package store

import (
	"strings"
	"testing"
	"time"
)

func exploitFinding(cve, severity, priority string, kev bool, epss float64) map[string]any {
	finding := map[string]any{"id": cve, "package": "openssl", "installed_version": "1", "fixed_version": "2",
		"severity": severity, "priority": priority, "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N"}
	exploit := map[string]any{"kev": kev}
	if kev {
		exploit["kev_due"], exploit["ransomware"] = "2026-01-23", true
	}
	if epss > 0 {
		exploit["epss"], exploit["epss_percentile"] = epss, 0.9
	}
	finding["exploit"] = exploit
	return finding
}

func TestExploitDataIsStoredAndRanked(t *testing.T) {
	withTempDataDir(t)
	first := addTestHost(t, "a.example", TransportLocal)
	second := addTestHost(t, "b.example", TransportLocal)
	complete := func(host Host, findings ...any) Scan {
		scan, err := CreateScan(host, []string{CheckPackages})
		if err != nil {
			t.Fatal(err)
		}
		if err := CompleteScan(scan.ID, map[string]any{
			"host_id": host.ID, "address": host.Address, "os": "Ubuntu 24.04 LTS", "findings": findings,
			"exploit_data": map[string]any{"kev": map[string]any{"available": true}, "epss": map[string]any{"available": false}},
		}); err != nil {
			t.Fatal(err)
		}
		done, err := GetScan(scan.ID)
		if err != nil {
			t.Fatal(err)
		}
		return done
	}
	scan := complete(first,
		exploitFinding("CVE-2026-1", "LOW", "exploited", true, 0),
		exploitFinding("CVE-2026-2", "MEDIUM", "likely", false, 0.42),
		exploitFinding("CVE-2026-3", "CRITICAL", "severe", false, 0.01),
		// The same CVE in another binary package counts once.
		exploitFinding("CVE-2026-1", "LOW", "exploited", true, 0))
	if scan.Exploit != (ExploitCounts{Known: 1, KnownFixable: 1, Likely: 1, Data: true}) {
		t.Fatalf("counts: %+v", scan.Exploit)
	}
	complete(second, exploitFinding("CVE-2026-3", "CRITICAL", "severe", false, 0.05))
	if points, err := Trends(1, TrendFilter{}, time.Now()); err != nil || points[0] != (TrendPoint{
		Day: time.Now().UTC().Format(time.DateOnly), Hosts: 2, Critical: 2, Medium: 1, Low: 2, Exploited: 1, Likely: 1,
	}) {
		t.Fatalf("today's trend: %+v %v", points, err)
	}

	vulnerabilities, err := Vulnerabilities()
	if err != nil {
		t.Fatal(err)
	}
	order := make([]string, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		order = append(order, vulnerability.CVE)
	}
	if strings.Join(order, " ") != "CVE-2026-1 CVE-2026-2 CVE-2026-3" {
		t.Fatalf("order by priority, not severity: %v", order)
	}
	if top := vulnerabilities[0]; !top.KEV || top.KEVDue != "2026-01-23" || !top.Ransomware || top.Priority != "exploited" || top.CVSSScore != 7.5 {
		t.Fatalf("KEV vulnerability: %+v", top)
	}
	if shared := vulnerabilities[2]; shared.HostCount != 2 || shared.EPSS == nil || *shared.EPSS != 0.05 {
		t.Fatalf("highest EPSS across hosts: %+v", shared)
	}

	// A scan without exploit data says so, rather than "none exploited".
	plain, err := CreateScan(first, []string{CheckPackages})
	if err != nil {
		t.Fatal(err)
	}
	if err := CompleteScan(plain.ID, map[string]any{"host_id": first.ID, "findings": []any{exploitFinding("CVE-2026-1", "LOW", "severe", false, 0)}}); err != nil {
		t.Fatal(err)
	}
	if done, _ := GetScan(plain.ID); done.Exploit.Data {
		t.Fatalf("no exploit data: %+v", done.Exploit)
	}
}

func TestTrendsCarryEachHostForward(t *testing.T) {
	withTempDataDir(t)
	first := addTestHost(t, "a.example", TransportLocal)
	second := addTestHost(t, "b.example", TransportLocal)
	db, err := database()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		host                      string
		day                       string
		critical, high, exploited int
	}{
		{first.ID, "2026-10-01", 2, 5, 1},
		{first.ID, "2026-10-03", 1, 4, 0},
		{second.ID, "2026-10-02", 0, 3, 2},
	} {
		if _, err := db.Exec("INSERT INTO host_trends (host_id, day, critical, high, exploited) VALUES (?, ?, ?, ?, ?)",
			row.host, row.day, row.critical, row.high, row.exploited); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SetHostTags(second.ID, []string{" Prod ", "prod", "team:web"}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 15, 0, 0, 0, time.UTC)
	points, err := Trends(4, TrendFilter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []TrendPoint{
		{Day: "2026-10-01", Hosts: 1, Critical: 2, High: 5, Exploited: 1},
		{Day: "2026-10-02", Hosts: 2, Critical: 2, High: 8, Exploited: 3},
		{Day: "2026-10-03", Hosts: 2, Critical: 1, High: 7, Exploited: 2},
		{Day: "2026-10-04", Hosts: 2, Critical: 1, High: 7, Exploited: 2},
	}
	for index := range want {
		if points[index] != want[index] {
			t.Errorf("day %d: %+v, want %+v", index, points[index], want[index])
		}
	}
	tagged, err := Trends(4, TrendFilter{Tag: "prod"}, now)
	if err != nil || tagged[3].Hosts != 1 || tagged[3].High != 3 || tagged[0].Hosts != 0 {
		t.Fatalf("by tag: %+v %v", tagged, err)
	}
	single, err := Trends(1, TrendFilter{HostID: first.ID}, now)
	if err != nil || len(single) != 1 || single[0].High != 4 {
		t.Fatalf("one host: %+v %v", single, err)
	}
	if _, err := Trends(0, TrendFilter{}, now); err == nil {
		t.Fatal("0 days accepted")
	}
	// Removing a host removes it from trends.
	if _, err := RemoveHost(first.ID); err != nil {
		t.Fatal(err)
	}
	if points, _ := Trends(1, TrendFilter{}, now); points[0].Hosts != 1 {
		t.Fatalf("after removing a host: %+v", points)
	}
}

func TestTagsAreNormalizedAndChecked(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "a.example", TransportLocal)
	tags, err := SetHostTags(host.ID, []string{"Web", "prod", "", "web", "eu-west-1"})
	if err != nil || strings.Join(tags, ",") != "eu-west-1,prod,web" {
		t.Fatalf("%v %v", tags, err)
	}
	for _, bad := range [][]string{{"has space"}, {"-leading"}, {strings.Repeat("a", 41)}, {"<script>"}} {
		if _, err := SetHostTags(host.ID, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, MaxTags+1)
	for index := range many {
		many[index] = "t" + strings.Repeat("x", index)
	}
	if _, err := SetHostTags(host.ID, many); err == nil {
		t.Fatal("too many tags accepted")
	}
	if _, err := SetHostTags("missing", []string{"prod"}); err == nil {
		t.Fatal("tags for a missing host")
	}
	counts, err := Tags()
	if err != nil || len(counts) != 3 || counts[1] != (TagCount{"prod", 1}) {
		t.Fatalf("%+v %v", counts, err)
	}
	summaries, err := HostSummaries()
	if err != nil || strings.Join(summaries[0].Tags, ",") != "eu-west-1,prod,web" {
		t.Fatalf("%+v %v", summaries, err)
	}
	if _, err := SetHostTags(host.ID, nil); err != nil {
		t.Fatal(err)
	}
	if summaries, _ := HostSummaries(); summaries[0].Tags == nil || len(summaries[0].Tags) != 0 {
		t.Fatalf("cleared tags: %#v", summaries[0].Tags)
	}
}
