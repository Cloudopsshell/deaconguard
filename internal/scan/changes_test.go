package scan

import (
	"strings"
	"testing"

	"deaconguard/internal/checks"
)

func snapshot(sections map[string][]checks.SnapshotItem) *checks.Snapshot {
	return &checks.Snapshot{Root: true, Sections: sections}
}

func TestCompareSnapshots(t *testing.T) {
	ssh := checks.SnapshotItem{Key: "tcp *:22", Text: "TCP port 22, open to the network (sshd)", Exposed: true}
	before := snapshot(map[string][]checks.SnapshotItem{
		checks.SectionListening: {ssh, {Key: "tcp localhost:5432", Text: "TCP port 5432 on localhost (postgres)"}},
		checks.SectionUsers:     {{Key: "root uid 0", Text: "root (UID 0, /bin/bash)"}},
		checks.SectionKeys:      {{Key: "root SHA256:old", Text: "ED25519 key for root, SHA256:old"}},
		checks.SectionServices:  {},
	})

	findings, notes := CompareSnapshots(nil, before)
	if len(findings) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "first record") {
		t.Fatalf("first: %v %v", findings, notes)
	}
	if findings, _ := CompareSnapshots(before, before); len(findings) != 0 {
		t.Fatalf("unchanged: %v", findings)
	}

	after := snapshot(map[string][]checks.SnapshotItem{
		checks.SectionListening: {ssh, {Key: "tcp *:4444", Text: "TCP port 4444, open to the network (nc)", Exposed: true}},
		checks.SectionUsers:     {{Key: "root uid 0", Text: "root (UID 0, /bin/bash)"}, {Key: "toor uid 0", Text: "toor (UID 0, /bin/sh)"}},
		checks.SectionKeys:      {{Key: "root SHA256:old", Text: "ED25519 key for root, SHA256:old"}, {Key: "root SHA256:new", Text: "RSA key for root, SHA256:new", Root: true}},
		checks.SectionServices:  {{Key: "miner.service", Text: "miner.service"}},
		// Not in the previous record: not compared.
		checks.SectionCron: {{Key: "/etc/cron.d/x 1", Text: "/etc/cron.d/x: * * * * * root sh"}},
	})
	findings, notes = CompareSnapshots(before, after)
	got := map[string]string{}
	for _, f := range findings {
		got[f.Title] = f.Severity
	}
	want := map[string]string{
		"New login account: toor (UID 0, /bin/sh)":                        "CRITICAL",
		"New SSH key: RSA key for root, SHA256:new":                       "HIGH",
		"New listening port: TCP port 4444, open to the network (nc)":     "HIGH",
		"Port no longer listening: TCP port 5432 on localhost (postgres)": "LOW",
		"New enabled service: miner.service":                              "MEDIUM",
	}
	if len(got) != len(want) {
		t.Fatalf("findings: %v", got)
	}
	for title, severity := range want {
		if got[title] != severity {
			t.Fatalf("%s: %q in %v", title, got[title], got)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "scheduled jobs") {
		t.Fatalf("notes: %v", notes)
	}
}

func TestEvaluateChangesAddsFindings(t *testing.T) {
	before := snapshot(map[string][]checks.SnapshotItem{checks.SectionAdmins: {}})
	after := snapshot(map[string][]checks.SnapshotItem{checks.SectionAdmins: {{Key: "eve in sudo", Text: "eve (group sudo)"}}})
	report := map[string]any{"check_results": map[string]checks.Result{
		checks.Changes: {Status: checks.StatusCompleted, Summary: "Recorded 1 administrators", Findings: []checks.Finding{}, Snapshot: after},
	}}
	if err := EvaluateChanges(report, before); err != nil {
		t.Fatal(err)
	}
	result := report["check_results"].(map[string]checks.Result)[checks.Changes]
	if len(result.Findings) != 1 || result.Findings[0].Severity != "HIGH" || result.Findings[0].Rule != "DG-CHG-003" ||
		result.Summary != "Recorded 1 administrators; 1 change since the previous scan" {
		t.Fatalf("result: %+v", result)
	}
}
