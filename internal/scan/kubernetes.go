package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/checks"
	"deaconguard/internal/iac"
	"deaconguard/internal/kube"
)

// ClusterResult is a cluster scan as the Kubernetes check's result, which a
// cluster agent sends. The server adds the version's support and CVEs.
func ClusterResult(report kube.Report) checks.Result {
	result := checks.Result{Status: checks.StatusCompleted, Notes: report.Notes, Findings: []checks.Finding{},
		Cluster: &checks.Cluster{Name: report.Cluster, Version: report.Version, Nodes: report.Nodes, Architecture: report.Architecture,
			Namespaces: report.Namespaces, Workloads: report.Workloads, Images: report.Images, Running: report.Running, Inventory: report.Inventory}}
	if result.Notes == nil {
		result.Notes = []string{}
	}
	for _, f := range report.Findings {
		result.Findings = append(result.Findings, clusterFinding(f))
	}
	summarizeCluster(&result)
	return result
}

func clusterFinding(f iac.Finding) checks.Finding {
	return checks.Finding{Rule: f.Rule, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: f.File}
}

// summarizeCluster sorts the findings, most severe first, and writes the summary.
func summarizeCluster(result *checks.Result) {
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[strings.ToUpper(f.Severity)]++
	}
	var parts []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], strings.ToLower(severity)))
		}
	}
	cluster := result.Cluster
	result.Summary = fmt.Sprintf("Kubernetes %s, %d nodes, %d workloads: %d findings", cluster.Version, cluster.Nodes, cluster.Workloads, len(result.Findings))
	if len(parts) > 0 {
		result.Summary += " (" + strings.Join(parts, ", ") + ")"
	}
}

// ClusterVersionChecks checks a Kubernetes version online; tests replace it.
var ClusterVersionChecks = func(ctx context.Context, version string) ([]iac.Finding, []string) {
	return kube.VersionFindings(ctx, version, kube.Options{Releases: kube.OnlineReleases, CVEs: kube.OnlineCVEs})
}

// EvaluateKubernetes adds the Kubernetes version's support and known CVEs to
// the cluster a cluster agent read, in place in the report's check results.
func EvaluateKubernetes(report map[string]any, emit func(Event)) error {
	raw, ok := report["check_results"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var results map[string]checks.Result
	if err := json.Unmarshal(encoded, &results); err != nil {
		return fmt.Errorf("read check results: %w", err)
	}
	result, ok := results[checks.Kubernetes]
	if !ok || result.Cluster == nil || result.Status == checks.StatusFailed {
		return nil
	}
	progress := &reporter{emit: emit}
	progress.startPhase(checks.Kubernetes, "Checking Kubernetes "+result.Cluster.Version+": its support and known vulnerabilities")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	findings, notes := ClusterVersionChecks(ctx, result.Cluster.Version)
	for _, f := range findings {
		result.Findings = append(result.Findings, clusterFinding(f))
	}
	result.Notes = append(result.Notes, notes...)
	summarizeCluster(&result)
	progress.findings(result)
	progress.endPhase(result.Status, result.Summary)
	results[checks.Kubernetes] = result
	report["check_results"] = results
	return nil
}

// RunCluster is a cluster agent's scan: the Kubernetes check of the cluster
// client reaches, as a report like a machine's, for the server to complete.
func RunCluster(ctx context.Context, client *kube.Client, name, hostID string, emit func(Event)) (map[string]any, error) {
	progress := &reporter{emit: emit}
	progress.startPhase(PhaseConnect, "Connecting to the Kubernetes API at "+client.Server)
	version, err := client.ServerVersion(ctx)
	if err != nil {
		progress.endPhase(checks.StatusFailed, err.Error())
		return nil, err
	}
	progress.endPhase(checks.StatusCompleted, "Kubernetes "+version.GitVersion)
	progress.startPhase(checks.Kubernetes, "Reading the cluster through the Kubernetes API, read-only")
	started := time.Now()
	cluster, err := kube.Scan(ctx, client, kube.Options{})
	if errors.Is(err, kube.ErrForbidden) {
		err = fmt.Errorf("%w: give the agent's service account the deaconguard-cluster-scan ClusterRole", err)
	}
	if err != nil {
		progress.endPhase(checks.StatusFailed, err.Error())
		return nil, err
	}
	cluster.Cluster = name
	result := ClusterResult(cluster)
	progress.findings(result)
	progress.endPhase(result.Status, fmt.Sprintf("%s · %s", result.Summary, formatDuration(time.Since(started))))
	return map[string]any{
		"host_id": hostID, "address": name, "os": "Kubernetes " + cluster.Version,
		"scanned_at": time.Now().UTC().Format(time.RFC3339), "checks_run": []string{checks.Kubernetes},
		"deaconguard_version": buildinfo.Version,
		"check_results":       map[string]checks.Result{checks.Kubernetes: result},
	}, nil
}
