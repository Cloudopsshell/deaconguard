package scan

import (
	"strings"
	"testing"

	"deaconguard/internal/checks"
)

func TestSharedKeyFindings(t *testing.T) {
	keys := []checks.SnapshotItem{
		{Key: "deploy SHA256:shared", Text: "ssh-ed25519 key for deploy, SHA256:shared (ops@laptop)"},
		{Key: "backup SHA256:shared", Text: "ssh-ed25519 key for backup, SHA256:shared (ops@laptop)"},
		{Key: "root SHA256:pair", Text: "ssh-rsa key for root, SHA256:pair", Root: true},
		{Key: "app SHA256:alone", Text: "ssh-ed25519 key for app, SHA256:alone"},
	}
	others := map[string][]KeyHost{
		"SHA256:shared": {{Host: "web-1", Account: "deploy"}, {Host: "web-2", Account: "deploy"}, {Host: "db-1", Account: "root", Root: true}, {Host: "web-1", Account: "ops"}},
		"SHA256:pair":   {{Host: "web-1", Account: "root", Root: true}},
	}
	findings := SharedKeyFindings(keys, others)
	if len(findings) != 1 {
		t.Fatalf("findings: %+v", findings)
	}
	finding := findings[0]
	if finding.Rule != checks.RuleSharedKey || finding.Severity != "HIGH" || finding.Title != "The SSH key SHA256:shared (ops@laptop) is trusted on 4 machines" {
		t.Fatalf("finding: %+v", finding)
	}
	if !strings.Contains(finding.Detail, "here as deploy, backup, and on web-1 (deploy), web-2 (deploy), db-1 (root).") {
		t.Fatalf("detail: %s", finding.Detail)
	}
	if strings.Join(finding.Path, " > ") != "whoever has the key > logs in here as deploy, backup > and on 3 other machines" {
		t.Fatalf("path: %v", finding.Path)
	}

	report := map[string]any{"check_results": map[string]checks.Result{checks.Paths: {Status: checks.StatusCompleted, Summary: "0 ways to root, 0 secrets readable by others",
		Findings: []checks.Finding{{Rule: checks.RuleEnvFile, Severity: "MEDIUM"}}, Keys: keys}}}
	if err := EvaluateSharedKeys(report, others); err != nil {
		t.Fatal(err)
	}
	result := report["check_results"].(map[string]checks.Result)[checks.Paths]
	if len(result.Findings) != 2 || result.Findings[0].Rule != checks.RuleSharedKey || !strings.HasSuffix(result.Summary, "; 1 SSH key trusted on many machines") {
		t.Fatalf("result: %+v", result)
	}
}
