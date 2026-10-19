package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/iac"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

func enrollTestCluster(t *testing.T, s *Server, cookie *http.Cookie, name string) (string, string) {
	t.Helper()
	created := do(t, s, call{method: http.MethodPost, path: "/api/enrollment-tokens", body: map[string]string{"server_url": testOrigin}, cookie: cookie})
	token, err := agentapi.ParseToken(decode[enrollmentTokenResponse](t, created).Token)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: agentapi.EnrollRequest{
		Secret: token.Secret, Hostname: name, Username: "kubernetes", OS: "Kubernetes", Version: "1.5.0", Kind: store.KindCluster,
	}})
	identity := decode[agentapi.EnrollResponse](t, enrolled)
	return identity.HostID, identity.HostID + "." + identity.Credential
}

func TestClustersRunOnlyTheKubernetesCheck(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	scan.ClusterVersionChecks = func(_ context.Context, version string) ([]iac.Finding, []string) {
		return []iac.Finding{iac.NewFinding("DG-K8S-032", "k8s/_cluster/version/1.29.3", 1, "Kubernetes 1.29.3 is past its end of life", "Upgrade.")}, nil
	}
	t.Cleanup(func() { scan.ClusterVersionChecks = nil })
	clusterID, bearer := enrollTestCluster(t, s, cookie, "prod-eu")
	machineID, _ := enrollTestAgent(t, s, cookie, "web-01", "1.5.0")

	if host, _ := store.GetHost(clusterID); !host.IsCluster() || host.Address != "prod-eu" {
		t.Fatalf("cluster host = %+v", host)
	}
	if bad := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: agentapi.EnrollRequest{Secret: "x", Hostname: "y", Kind: "router"}}); bad.Code != http.StatusBadRequest {
		t.Fatalf("an unknown kind: %d", bad.Code)
	}
	if refused := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + clusterID + "/scans", cookie: cookie, body: map[string]any{"checks": []string{"packages"}}}); refused.Code == http.StatusAccepted ||
		!strings.Contains(refused.Body.String(), "only the Kubernetes check") {
		t.Fatalf("packages on a cluster: %d %s", refused.Code, refused.Body.String())
	}
	if refused := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + machineID + "/scans", cookie: cookie, body: map[string]any{"checks": []string{"kubernetes"}}}); refused.Code == http.StatusAccepted ||
		!strings.Contains(refused.Body.String(), "runs on clusters") {
		t.Fatalf("kubernetes on a machine: %d %s", refused.Code, refused.Body.String())
	}
	if refused := do(t, s, call{method: http.MethodPatch, path: "/api/hosts/" + clusterID, cookie: cookie, body: map[string]any{"auto_scan_containers": true}}); refused.Code != http.StatusBadRequest {
		t.Fatalf("container auto-scan on a cluster: %d", refused.Code)
	}

	queued := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + clusterID + "/scans", cookie: cookie, body: map[string]any{"checks": []string{"kubernetes"}}})
	if queued.Code != http.StatusAccepted {
		t.Fatalf("kubernetes on a cluster: %d %s", queued.Code, queued.Body.String())
	}
	job := decode[agentapi.Job](t, do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer,
		headers: map[string]string{agentapi.HeaderVersion: "1.5.0"}}))
	if strings.Join(job.Checks, ",") != "kubernetes" {
		t.Fatalf("job %+v", job)
	}
	result := map[string]any{"report": map[string]any{
		"address": "prod-eu", "os": "Kubernetes v1.29.3", "checks_run": []string{"kubernetes"},
		"check_results": map[string]any{"kubernetes": map[string]any{
			"status": "completed", "summary": "1 finding", "notes": []string{},
			"cluster":  map[string]any{"name": "prod-eu", "version": "v1.29.3", "nodes": 3, "namespaces": 5, "workloads": 12},
			"findings": []map[string]any{{"rule": "DG-K8S-001", "severity": "CRITICAL", "title": "Deployment shop/web: container web is privileged", "detail": "", "evidence": "k8s/shop/deployment/web"}},
		}},
	}}
	if response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/scans/" + job.ScanID + "/result", body: result, bearer: bearer,
		headers: map[string]string{agentapi.HeaderVersion: "1.5.0"}}); response.Code != http.StatusAccepted {
		t.Fatalf("result: %d %s", response.Code, response.Body.String())
	}
	s.runner.wait()
	detail := decode[scanDetail](t, do(t, s, call{method: http.MethodGet, path: "/api/scans/" + job.ScanID, cookie: cookie}))
	if detail.Scan.Status != store.ScanSucceeded {
		t.Fatalf("scan: %+v", detail.Scan)
	}
	results := detail.Report["check_results"].(map[string]any)["kubernetes"].(map[string]any)
	findings := results["findings"].([]any)
	if len(findings) != 2 || !strings.Contains(results["summary"].(string), "Kubernetes v1.29.3, 3 nodes, 12 workloads: 2 findings (1 critical, 1 high)") {
		t.Fatalf("the server didn't add the version's findings: %v", results)
	}

	// A schedule runs each host's own checks: packages on the machine, the
	// Kubernetes check on the cluster.
	created := decode[scheduleView](t, do(t, s, call{method: http.MethodPost, path: "/api/schedules", cookie: cookie, body: map[string]any{
		"name": "Nightly", "checks": []string{"packages", "kubernetes"}, "all_hosts": true, "days": []int{0, 1, 2, 3, 4, 5, 6}, "time": "02:30", "timezone": "UTC",
	}}))
	next, _ := time.Parse(time.RFC3339, created.NextRunAt)
	s.runDueSchedules(next)
	clusterScan, _, _ := store.UnfinishedScan(clusterID)
	machineScan, _, _ := store.UnfinishedScan(machineID)
	if strings.Join(clusterScan.Checks, ",") != "kubernetes" || strings.Join(machineScan.Checks, ",") != "packages" {
		t.Fatalf("schedule: cluster %v, machine %v", clusterScan.Checks, machineScan.Checks)
	}
}
