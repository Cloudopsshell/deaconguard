package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/checks"
	"deaconguard/internal/kube"
	"deaconguard/internal/scan"
)

func TestClusterAgentScansItsCluster(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			json.NewEncoder(w).Encode(map[string]string{"gitVersion": "v1.31.6"})
			return
		}
		items := []any{}
		if r.URL.Path == "/apis/apps/v1/deployments" {
			items = append(items, map[string]any{"metadata": map[string]any{"name": "web", "namespace": "shop"},
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{
					map[string]any{"name": "web", "image": "nginx:1.27", "securityContext": map[string]any{"privileged": true}}}}}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": items})
	}))
	defer api.Close()
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600)
	kubeconfig := filepath.Join(dir, "config")
	os.WriteFile(kubeconfig, []byte(fmt.Sprintf("current-context: c\ncontexts: [{name: c, context: {cluster: c, user: u}}]\n"+
		"clusters: [{name: c, cluster: {server: %s, certificate-authority: ca.crt}}]\nusers: [{name: u, user: {token: t}}]\n", api.URL)), 0o600)
	connectCluster = func() (*kube.Client, error) { return kube.Connect(kubeconfig, "") }
	t.Cleanup(func() { connectCluster = func() (*kube.Client, error) { return kube.Connect("", "") } })

	var events []scan.Event
	config := Config{HostID: "h1", Cluster: "prod-eu"}
	if _, err := scanCluster(context.Background(), config, agentapi.Job{Checks: []string{"packages"}}, func(e scan.Event) {}); err == nil {
		t.Fatal("a cluster agent ran the package check")
	}
	report, err := scanCluster(context.Background(), config, agentapi.Job{Checks: []string{checks.Kubernetes}}, func(e scan.Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	result := report["check_results"].(map[string]checks.Result)[checks.Kubernetes]
	if report["address"] != "prod-eu" || report["os"] != "Kubernetes v1.31.6" || result.Cluster == nil || result.Cluster.Name != "prod-eu" ||
		result.Findings[0].Rule != "DG-K8S-001" || result.Findings[0].Evidence != "k8s/shop/deployment/web" {
		t.Fatalf("report %v, result %+v", report, result)
	}
	if len(events) == 0 || !strings.Contains(events[len(events)-1].Message, "Kubernetes v1.31.6") {
		t.Fatalf("events %+v", events)
	}
	t.Setenv("DEACONGUARD_AGENT_CLUSTER", " prod-eu ")
	if ClusterName() != "prod-eu" || (Config{Cluster: "prod-eu"}).Name() != "prod-eu" {
		t.Fatal("ClusterName")
	}
}
