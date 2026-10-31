package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/iac"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

func TestClusterViewPutsNodesAndPodsUnderTheCluster(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	scan.ClusterVersionChecks = func(context.Context, string) ([]iac.Finding, []string) { return nil, nil }
	t.Cleanup(func() { scan.ClusterVersionChecks = nil })
	s.agents.clusterImages = &fakeClusterImages{}
	clusterID, bearer := enrollTestCluster(t, s, cookie, "prod")
	nodeID, _ := enrollTestAgent(t, s, cookie, "node-1", "1.21.0")
	containerID := strings.Repeat("c", 64)

	// The node agent's latest Running containers and malware results.
	node, _ := store.GetHost(nodeID)
	record, err := store.CreateScan(node, []string{"containers", "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteScan(record.ID, map[string]any{"checks_run": []string{"containers", "malware"}, "check_results": map[string]any{
		"containers": map[string]any{"status": "completed", "summary": "", "notes": []string{}, "findings": []any{},
			"containers": []map[string]any{{"id": containerID, "name": "web", "image": "nginx:1.25", "state": "running", "packages": 120, "libraries": 0,
				"severity": map[string]int{"HIGH": 2, "MEDIUM": 3}, "exploited": 0, "fixable": 2}}},
		"malware": map[string]any{"status": "completed", "summary": "", "notes": []string{}, "findings": []map[string]any{
			{"rule": "DG-MAL-001", "severity": "HIGH", "title": "web: an executable in /tmp", "detail": "", "evidence": "/tmp/x", "container": "web", "container_id": containerID}}},
	}}); err != nil {
		t.Fatal(err)
	}

	queued := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + clusterID + "/scans", cookie: cookie, body: map[string]any{"checks": []string{"kubernetes"}}})
	if queued.Code != http.StatusAccepted {
		t.Fatalf("scan: %d %s", queued.Code, queued.Body.String())
	}
	job := decode[agentapi.Job](t, do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer, headers: map[string]string{agentapi.HeaderVersion: "1.21.0"}}))
	inventory := map[string]any{
		"nodes":      []map[string]any{{"name": "node-1", "ready": true, "roles": []string{"control-plane"}, "os_image": "Ubuntu 26.04 LTS"}, {"name": "node-2", "ready": true}},
		"namespaces": []string{"kube-system", "shop", "empty"},
		"pods": []map[string]any{
			{"namespace": "shop", "name": "web-7d9-abc", "workload_kind": "Deployment", "workload": "web", "node": "node-1", "phase": "Running",
				"containers": []map[string]any{{"name": "web", "image": "nginx:1.25", "id": containerID, "ready": true, "restarts": 1, "state": "running"}}},
			{"namespace": "kube-system", "name": "coredns-1", "workload_kind": "Deployment", "workload": "coredns", "node": "node-2", "phase": "Running",
				"containers": []map[string]any{{"name": "coredns", "image": "coredns:1.11", "id": strings.Repeat("d", 64)}}},
		},
	}
	result := map[string]any{"report": map[string]any{"address": "prod", "os": "Kubernetes v1.34.1", "checks_run": []string{"kubernetes"},
		"check_results": map[string]any{"kubernetes": map[string]any{"status": "completed", "summary": "", "notes": []string{},
			"cluster": map[string]any{"name": "prod", "version": "v1.34.1", "nodes": 2, "namespaces": 3, "workloads": 2, "inventory": inventory},
			"findings": []map[string]any{
				{"rule": "DG-K8S-001", "severity": "HIGH", "title": "Deployment shop/web: container web is privileged", "detail": "", "evidence": "k8s/shop/deployment/web"},
				{"rule": "DG-K8S-030", "severity": "MEDIUM", "title": "Namespace shop: 1 pods and no NetworkPolicy", "detail": "", "evidence": "k8s/shop/namespace/shop"},
				{"rule": "DG-K8S-020", "severity": "HIGH", "title": "ClusterRoleBinding ci-admin gives cluster-admin", "detail": "", "evidence": "k8s/_cluster/clusterrolebinding/ci-admin"},
				{"rule": "DG-K8S-001", "severity": "HIGH", "title": "CronJob shop/backup: privileged", "detail": "", "evidence": "k8s/shop/cronjob/backup"},
			}}}}}
	if response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/scans/" + job.ScanID + "/result", body: result, bearer: bearer,
		headers: map[string]string{agentapi.HeaderVersion: "1.21.0"}}); response.Code != http.StatusAccepted {
		t.Fatalf("result: %d %s", response.Code, response.Body.String())
	}
	s.runner.wait()

	if host, _ := store.GetHost(nodeID); host.ClusterID != clusterID {
		t.Fatalf("the node isn't linked to its cluster: %+v", host)
	}
	view := decode[clusterView](t, do(t, s, call{method: http.MethodGet, path: "/api/hosts/" + clusterID + "/cluster", cookie: cookie}))
	if !view.Inventory || view.Version != "v1.34.1" || view.Pods != 2 || view.Containers != 2 {
		t.Fatalf("view: %+v", view)
	}
	if len(view.Nodes) != 2 || view.Nodes[0].Host == nil || view.Nodes[0].Host.ID != nodeID || view.Nodes[0].Pods != 1 || view.Nodes[1].Host != nil {
		t.Fatalf("nodes: %+v", view.Nodes)
	}
	if len(view.Notes) != 1 || !strings.Contains(view.Notes[0], "1 of 2 nodes have no node agent") {
		t.Errorf("notes: %v", view.Notes)
	}
	if len(view.Findings) != 1 || view.Findings[0].Rule != "DG-K8S-020" {
		t.Errorf("the cluster's own findings: %+v", view.Findings)
	}
	// Namespaces with problems first, Kubernetes' own last.
	var names []string
	for _, namespace := range view.Namespaces {
		names = append(names, namespace.Name)
	}
	if strings.Join(names, ",") != "shop,empty,kube-system" {
		t.Fatalf("namespaces: %v", names)
	}
	shop := view.Namespaces[0]
	if shop.Counts.High != 2 || shop.Counts.Medium != 3 || shop.Counts.Malware != 1 || shop.Counts.Settings != 3 || len(shop.Findings) != 1 || shop.Pods != 1 {
		t.Errorf("shop: %+v", shop.Counts)
	}
	if len(shop.Workloads) != 2 {
		t.Fatalf("workloads: %+v", shop.Workloads)
	}
	web := shop.Workloads[0]
	if web.Kind != "Deployment" || web.Name != "web" || len(web.Findings) != 1 || len(web.Pods) != 1 || web.Pods[0].NodeHostID != nodeID || web.Pods[0].Restarts != 1 {
		t.Fatalf("web: %+v", web)
	}
	container := web.Pods[0].Containers[0]
	if container.Checked != "node" || container.Counts.High != 2 || container.Counts.Fixable != 2 || len(container.Malware) != 1 {
		t.Errorf("container: %+v", container)
	}
	if backup := shop.Workloads[1]; backup.Kind != "CronJob" || backup.Name != "backup" || len(backup.Pods) != 0 || backup.Counts.Settings != 1 {
		t.Errorf("a workload without pods: %+v", backup)
	}
	if !view.Namespaces[2].System {
		t.Errorf("kube-system isn't marked as Kubernetes' own")
	}
	if len(view.Images) != 2 || view.Images[0].Image != "nginx:1.25" || view.Images[0].Counts.High != 2 {
		t.Errorf("images: %+v", view.Images)
	}

	if machine := do(t, s, call{method: http.MethodGet, path: "/api/hosts/" + nodeID + "/cluster", cookie: cookie}); machine.Code != http.StatusNotFound {
		t.Errorf("a machine's cluster view: %d", machine.Code)
	}
}
