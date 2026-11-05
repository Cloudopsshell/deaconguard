package store

import (
	"testing"
	"time"
)

// Three nodes from one image have the same vulnerability; the cluster
// counts it once, lists the nodes it's on, and trends count the cluster.
func TestClusterFindingsCountedOnce(t *testing.T) {
	withTempDataDir(t)
	_, secret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	cluster, _, _ := enrollWith(t, secret, "prod", KindCluster)
	var nodes []Host
	for _, name := range []string{"node-1", "node-2", "node-3"} {
		node, _, _ := enrollWith(t, secret, name, "")
		nodes = append(nodes, node)
	}
	if err := LinkClusterNodes(cluster.ID, []string{"node-1", "node-2", "node-3"}); err != nil {
		t.Fatal(err)
	}
	server, _, _ := enrollWith(t, secret, "web-1", "")
	complete := func(host Host, findings []any, malware []any) {
		scan, err := CreateScan(host, []string{CheckPackages, "malware"})
		if err != nil {
			t.Fatal(err)
		}
		if err := CompleteScan(scan.ID, map[string]any{
			"host_id": host.ID, "address": host.Address, "checks_run": []any{CheckPackages, "malware"}, "findings": findings,
			"check_results": map[string]any{"malware": map[string]any{"status": "completed", "findings": malware}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	openssl := map[string]any{"id": "CVE-2026-1", "package": "openssl", "installed_version": "3.0.1", "fixed_version": "3.0.2", "severity": "HIGH", "fix": "available"}
	curl := map[string]any{"id": "CVE-2026-2", "package": "curl", "installed_version": "8.5", "fixed_version": "", "severity": "MEDIUM", "fix": "none"}
	miner := map[string]any{"rule": "DG-MAL-001", "severity": "CRITICAL", "title": "Crypto miner", "evidence": "/tmp/xmrig"}
	complete(nodes[0], []any{openssl}, []any{miner})
	complete(nodes[1], []any{openssl}, []any{miner})
	complete(nodes[2], []any{openssl, curl}, []any{})
	complete(server, []any{openssl}, []any{})

	packages, err := GetClusterFindings(cluster.ID, CheckPackages)
	if err != nil {
		t.Fatal(err)
	}
	if packages.Nodes != 3 || packages.Checked != 3 || len(packages.Vulnerabilities) != 2 || packages.Counts.High != 1 || packages.Counts.Medium != 1 {
		t.Fatalf("packages: %+v", packages)
	}
	if first := packages.Vulnerabilities[0]; first.Package != "openssl" || len(first.Nodes) != 3 || first.Fix != "available" {
		t.Fatalf("openssl: %+v", first)
	}
	malware, err := GetClusterFindings(cluster.ID, "malware")
	if err != nil || len(malware.Findings) != 1 || len(malware.Findings[0].Nodes) != 2 {
		t.Fatalf("malware: %+v %v", malware, err)
	}

	counts, err := ClusterCombinedCounts()
	if err != nil {
		t.Fatal(err)
	}
	if got := counts[cluster.ID]; got.Findings != 2 || got.Severity.High != 1 || got.Fixes.Counts["available"] != 1 || got.Scanned != 3 {
		t.Fatalf("combined: %+v", got)
	}
	summaries, _ := HostSummaries()
	for _, summary := range summaries {
		if summary.ID == cluster.ID && (summary.Nodes == nil || summary.Nodes.Findings != 2) {
			t.Fatalf("cluster summary nodes: %+v", summary.Nodes)
		}
	}
	// The cluster counts as one host with openssl, as does web-1.
	vulnerabilities, _ := Vulnerabilities()
	for _, vulnerability := range vulnerabilities {
		if vulnerability.CVE == "CVE-2026-1" && vulnerability.HostCount != 2 {
			t.Errorf("openssl on %d hosts, want 2 (the cluster and web-1)", vulnerability.HostCount)
		}
	}
	// Today: the cluster's 1 high and 1 medium, and web-1's high.
	points, err := Trends(1, TrendFilter{}, time.Now())
	if err != nil || points[0].Hosts != 2 || points[0].High != 2 || points[0].Medium != 1 {
		t.Fatalf("trend: %+v %v", points, err)
	}
	if points, _ := Trends(1, TrendFilter{HostID: nodes[2].ID}, time.Now()); points[0].Medium != 1 {
		t.Errorf("a node's own trend: %+v", points)
	}
}
