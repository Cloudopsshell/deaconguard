package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/checks"
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
	images := &fakeClusterImages{summaries: map[string]scan.ImageSummary{
		"nginx:1.25": {Fixable: 4, Exploited: 1, FixableSeverity: map[string]int{"HIGH": 4}, Urgent: []string{"CVE-2023-44487"}}}}
	s.agents.clusterImages = images

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
			"cluster": map[string]any{"name": "prod-eu", "version": "v1.29.3", "nodes": 3, "namespaces": 5, "workloads": 12, "architecture": "arm64",
				"running_images": []map[string]any{{"image": "nginx:1.25", "digest": "sha256:" + strings.Repeat("a", 64), "namespaces": []string{"shop"}, "pods": 2},
					{"image": "alpine:3.22", "namespaces": []string{"tools"}, "pods": 1}}},
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
	if len(findings) != 3 || !strings.Contains(results["summary"].(string), "Kubernetes v1.29.3, 3 nodes, 12 workloads: 3 findings (1 critical, 2 high)") {
		t.Fatalf("the server didn't add the version's and the images' findings: %v", results)
	}
	// The images the pods run are checked on the server, for the nodes' platform.
	if strings.Join(images.asked, ",") != "nginx:1.25 linux/arm64,alpine:3.22 linux/arm64" {
		t.Fatalf("images checked: %v", images.asked)
	}
	if !strings.Contains(fmt.Sprint(findings), "Image nginx:1.25 has vulnerabilities known to be exploited") {
		t.Fatalf("no image finding: %v", findings)
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

func TestClusterChangesAreScanned(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	clusterID, bearer := enrollTestCluster(t, s, cookie, "prod-eu")
	poll := func() *httptest.ResponseRecorder {
		return do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer,
			headers: map[string]string{agentapi.HeaderVersion: "1.5.0", agentapi.HeaderNewContainers: "3"}})
	}
	// Each poll finds a scan someone started, so none waits for work.
	manual := func() {
		t.Helper()
		if queued := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + clusterID + "/scans", cookie: cookie,
			body: map[string]any{"checks": []string{"kubernetes"}}}); queued.Code != http.StatusAccepted {
			t.Fatalf("queue: %d %s", queued.Code, queued.Body.String())
		}
	}
	// Off: changes are ignored, and not deferred.
	manual()
	response := poll()
	if response.Header().Get(agentapi.HeaderChangesDeferred) != "" {
		t.Fatal("deferred while off")
	}
	store.FailScan(decode[agentapi.Job](t, response).ScanID, "test")
	if on := do(t, s, call{method: http.MethodPatch, path: "/api/hosts/" + clusterID, cookie: cookie, body: map[string]any{"auto_scan_containers": true}}); on.Code != http.StatusOK {
		t.Fatalf("turn on: %d %s", on.Code, on.Body.String())
	}
	job := decode[agentapi.Job](t, poll())
	if strings.Join(job.Checks, ",") != "kubernetes" {
		t.Fatalf("job after changes: %+v", job)
	}
	store.FailScan(job.ScanID, "test")
	// Within a minute of that scan, more changes are deferred for later.
	manual()
	if response := poll(); response.Header().Get(agentapi.HeaderChangesDeferred) != "1" {
		t.Fatalf("changes right after a scan weren't deferred: %v", response.Header())
	}
}

func TestNewClusterFindingsAreNotified(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	scan.ClusterVersionChecks = func(context.Context, string) ([]iac.Finding, []string) { return nil, nil }
	t.Cleanup(func() { scan.ClusterVersionChecks = nil })
	h := newHook(t)
	channel := addChannel(t, s, cookie, map[string]any{"name": "k8s", "kind": "webhook", "config": map[string]any{"url": h.server.URL}, "events": []string{"cluster"}})
	clusterID, bearer := enrollTestCluster(t, s, cookie, "prod-eu")
	scanWith := func(findings ...map[string]any) {
		t.Helper()
		do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + clusterID + "/scans", cookie: cookie, body: map[string]any{"checks": []string{"kubernetes"}}})
		version := map[string]string{agentapi.HeaderVersion: "1.5.0"}
		job := decode[agentapi.Job](t, do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer, headers: version}))
		result := map[string]any{"report": map[string]any{"os": "Kubernetes v1.31.6", "checks_run": []string{"kubernetes"},
			"check_results": map[string]any{"kubernetes": map[string]any{"status": "completed", "notes": []string{}, "findings": findings,
				"cluster": map[string]any{"name": "prod-eu", "version": "v1.31.6"}}}}}
		do(t, s, call{method: http.MethodPost, path: "/agent/v1/scans/" + job.ScanID + "/result", body: result, bearer: bearer, headers: version})
		s.runner.wait()
		time.Sleep(10 * time.Millisecond) // scans started within one second sort by their IDs
	}
	privileged := map[string]any{"rule": "DG-K8S-001", "severity": "CRITICAL", "title": "Deployment shop/web: container web is privileged", "detail": "", "evidence": ""}
	admin := map[string]any{"rule": "DG-K8S-020", "severity": "HIGH", "title": "ClusterRoleBinding ci-admin: grants cluster-admin", "detail": "", "evidence": ""}
	low := map[string]any{"rule": "DG-K8S-013", "severity": "LOW", "title": "Deployment shop/web: container web has no memory limit", "detail": "", "evidence": ""}
	scanWith(privileged, low)
	scanWith(privileged, admin, low)
	scanWith(privileged, admin, low)
	deliveries, err := store.Deliveries(channel.ID, 10)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries: %+v %v", deliveries, err)
	}
	titles := deliveries[0].Title + " | " + deliveries[1].Title
	if strings.Count(titles, "prod-eu: 1 new critical or high finding") != 2 {
		t.Fatalf("titles: %s", titles)
	}
}

type fakeClusterImages struct {
	summaries map[string]scan.ImageSummary
	asked     []string
}

func (f *fakeClusterImages) Cached(image checks.RunningImage, platform string) (scan.ImageSummary, error, bool) {
	return scan.ImageSummary{}, nil, false
}

func (f *fakeClusterImages) Check(_ context.Context, image checks.RunningImage, platform string) (scan.ImageSummary, error) {
	f.asked = append(f.asked, image.Image+" "+platform)
	return f.summaries[image.Image], nil
}
