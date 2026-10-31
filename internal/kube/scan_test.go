package kube

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/checks"
)

// fakeAPI serves a small cluster to the token "secret".
func fakeAPI(t *testing.T) *httptest.Server {
	lists := map[string][]map[string]any{
		"/api/v1/nodes": {{"metadata": map[string]any{"name": "n1", "labels": map[string]any{"node-role.kubernetes.io/control-plane": "true"}},
			"status": map[string]any{"nodeInfo": map[string]any{"architecture": "arm64", "osImage": "Ubuntu 26.04 LTS", "kernelVersion": "7.0.0-22-generic",
				"containerRuntimeVersion": "containerd://2.2.3", "kubeletVersion": "v1.29.3"},
				"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
				"addresses":  []any{map[string]any{"type": "InternalIP", "address": "10.0.0.5"}}}}},
		"/api/v1/namespaces": {
			{"metadata": map[string]any{"name": "shop"}},
			{"metadata": map[string]any{"name": "safe", "labels": map[string]any{"pod-security.kubernetes.io/enforce": "restricted"}}},
			{"metadata": map[string]any{"name": "empty"}},
			{"metadata": map[string]any{"name": "kube-system"}},
		},
		"/api/v1/pods": {
			// Owned by a ReplicaSet: checked through its Deployment.
			{"metadata": map[string]any{"name": "web-1", "namespace": "shop", "ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "web-abc", "controller": true}}},
				"spec": map[string]any{"nodeName": "n1", "containers": []any{map[string]any{"name": "web", "image": "nginx:1.27"}}},
				"status": map[string]any{"phase": "Running", "containerStatuses": []any{map[string]any{"name": "web", "image": "docker.io/library/nginx:1.27",
					"imageID": "docker.io/library/nginx@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "containerID": "containerd://c0ffee",
					"ready": true, "restartCount": 2, "state": map[string]any{"running": map[string]any{}}}}}},
			// A bare, privileged pod.
			{"metadata": map[string]any{"name": "debug", "namespace": "shop"},
				"spec": map[string]any{"containers": []any{map[string]any{"name": "sh", "image": "busybox:1.36", "securityContext": map[string]any{"privileged": true}}}}},
			{"metadata": map[string]any{"name": "app", "namespace": "safe", "ownerReferences": []any{map[string]any{"kind": "ReplicaSet"}}},
				"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "ghcr.io/acme/app:2"}}}},
			// kubeadm's API server: its flags are checked; the pod itself is Kubernetes'.
			{"metadata": map[string]any{"name": "kube-apiserver-cp", "namespace": "kube-system", "labels": map[string]any{"component": "kube-apiserver"}},
				"spec": map[string]any{"containers": []any{map[string]any{"name": "kube-apiserver", "image": "registry.k8s.io/kube-apiserver:v1.29.3",
					"command":         []any{"kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false", "--audit-log-path=/var/log/audit.log"},
					"securityContext": map[string]any{"privileged": true}}}}},
		},
		"/apis/apps/v1/deployments": {
			{"metadata": map[string]any{"name": "web", "namespace": "shop"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"hostNetwork": true, "containers": []any{map[string]any{"name": "web", "image": "nginx:1.27"}}}}}},
		},
		"/apis/apps/v1/statefulsets": {
			{"metadata": map[string]any{"name": "dashboard", "namespace": "default", "labels": map[string]any{"k8s-app": "kubernetes-dashboard"}},
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{}}}}},
		},
		"/apis/apps/v1/replicasets": {
			{"metadata": map[string]any{"name": "web-abc", "namespace": "shop", "ownerReferences": []any{map[string]any{"kind": "Deployment", "name": "web", "controller": true}}},
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"hostNetwork": true}}}},
		},
		"/apis/networking.k8s.io/v1/networkpolicies": {{"metadata": map[string]any{"name": "deny", "namespace": "safe"}}},
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": {
			{"metadata": map[string]any{"name": "cluster-admin", "labels": map[string]any{"kubernetes.io/bootstrapping": "rbac-defaults"}},
				"roleRef": map[string]any{"kind": "ClusterRole", "name": "cluster-admin"}},
			{"metadata": map[string]any{"name": "ci-admin"}, "roleRef": map[string]any{"kind": "ClusterRole", "name": "cluster-admin"}},
		},
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("a %s request: the scan must only read", r.Method)
		}
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]string{"gitVersion": "v1.29.3", "platform": "linux/arm64"})
			return
		case "/apis/batch/v1/cronjobs":
			w.WriteHeader(http.StatusForbidden)
			return
		}
		items := lists[r.URL.Path]
		// Pages of one, to exercise continue.
		page, next := items, ""
		if r.URL.Path == "/api/v1/namespaces" {
			start := 0
			fmt.Sscanf(r.URL.Query().Get("continue"), "%d", &start)
			page = items[start : start+1]
			if start+1 < len(items) {
				next = fmt.Sprint(start + 1)
			}
		}
		if page == nil {
			page = []map[string]any{}
		}
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"continue": next}, "items": page})
	}))
	return server
}

func writeKubeconfig(t *testing.T, server *httptest.Server, user string) string {
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600)
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: test
contexts:
  - name: test
    context: {cluster: test, user: me}
  - name: other
    context: {cluster: missing, user: me}
clusters:
  - name: test
    cluster: {server: %s, certificate-authority: ca.crt}
users:
  - name: me
    user:
%s
`, server.URL, user)
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte(config), 0o600)
	return path
}

func TestScanReadsTheCluster(t *testing.T) {
	server := fakeAPI(t)
	defer server.Close()
	client, err := Connect(writeKubeconfig(t, server, "      token: secret"), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	report, err := Scan(context.Background(), client, Options{
		Now: now,
		Releases: func(context.Context) ([]Release, error) {
			return []Release{{Cycle: "1.29", EOL: "2025-02-28", Latest: "1.29.15"}}, nil
		},
		CVEs: func(_ context.Context, version string) ([]checks.Finding, error) {
			if version != "1.29.3" {
				t.Errorf("CVEs of %s", version)
			}
			return []checks.Finding{{Rule: "GHSA-test", Severity: "HIGH", Title: "k8s.io/kubernetes 1.29.3 (Go): a flaw", Detail: "Fixed in 1.29.4."}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Version != "v1.29.3" || report.Nodes != 1 || report.Architecture != "arm64" || report.Namespaces != 4 {
		t.Errorf("report: %+v", report)
	}
	var ids []string
	for _, f := range report.Findings {
		ids = append(ids, f.Rule)
		if f.Title == "" || f.File == "" {
			t.Errorf("finding without title or source: %+v", f)
		}
	}
	for _, want := range []string{"DG-K8S-001", "DG-K8S-002", "DG-K8S-020", "DG-K8S-030", "DG-K8S-031", "DG-K8S-032", "DG-K8S-033", "DG-K8S-043", "DG-K8S-044", "GHSA-test"} {
		if !slices.Contains(ids, want) {
			t.Errorf("no %s in %v", want, ids)
		}
	}
	stig := map[string]string{}
	for _, f := range report.Findings {
		stig[f.Rule] = strings.Join(f.STIG, ",")
		if len(f.STIG) > 0 && !strings.Contains(f.Detail, "DISA Kubernetes STIG: "+strings.Join(f.STIG, ", ")) {
			t.Errorf("the detail doesn't name the STIG: %+v", f)
		}
	}
	for rule, ids := range map[string]string{"DG-K8S-034": "V-242383", "DG-K8S-045": "V-242395", "DG-K8S-043": "V-274882", "GHSA-test": "V-242443", "DG-K8S-001": ""} {
		if stig[rule] != ids {
			t.Errorf("%s has STIG %q; want %q", rule, stig[rule], ids)
		}
	}
	for _, unwanted := range []string{"DG-K8S-040", "DG-K8S-041", "DG-K8S-042"} {
		if slices.Contains(ids, unwanted) {
			t.Errorf("%s fired, though the API server sets it", unwanted)
		}
	}
	hostNetwork, privileged, admins := 0, 0, 0
	for _, f := range report.Findings {
		switch {
		case f.Rule == "DG-K8S-002":
			hostNetwork++
			if !strings.HasPrefix(f.Title, "Deployment shop/web:") {
				t.Errorf("hostNetwork reported on %s, not the Deployment", f.Title)
			}
		case f.Rule == "DG-K8S-001":
			privileged++
		case f.Rule == "DG-K8S-020":
			admins++
		case f.Rule == "DG-K8S-030" && !strings.Contains(f.Title, "shop"):
			t.Errorf("a NetworkPolicy finding for %s", f.Title)
		}
	}
	if hostNetwork != 1 || privileged != 1 || admins != 1 {
		t.Errorf("hostNetwork %d, privileged %d (the bare pod, not the API server), cluster-admin %d (not the built-in binding)", hostNetwork, privileged, admins)
	}
	if report.Findings[0].Severity != "CRITICAL" {
		t.Errorf("not sorted: %+v", report.Findings[0])
	}
	if !slices.Contains(report.Images, "busybox:1.36") || !slices.Contains(report.Images, "nginx:1.27") {
		t.Errorf("images = %v", report.Images)
	}
	// The build each pod runs, from its status.
	var nginx []checks.RunningImage
	for _, image := range report.Running {
		if image.Image == "nginx:1.27" {
			nginx = append(nginx, image)
		}
	}
	if len(nginx) != 1 || nginx[0].Digest != "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || nginx[0].Pods != 1 || strings.Join(nginx[0].Namespaces, ",") != "shop" {
		t.Errorf("running nginx = %+v", nginx)
	}
	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, "CronJobs weren't checked") || !strings.Contains(notes, "were left out") {
		t.Errorf("notes = %s", notes)
	}

	// The inventory, for the cluster view: pods under the workload people
	// manage, with the containers' IDs and builds.
	inventory := report.Inventory
	if inventory == nil || len(inventory.Nodes) != 1 || len(inventory.Namespaces) != 4 || len(inventory.Pods) != 4 {
		t.Fatalf("inventory: %+v", inventory)
	}
	node := inventory.Nodes[0]
	if node.Name != "n1" || !node.Ready || strings.Join(node.Roles, ",") != "control-plane" || node.Address != "10.0.0.5" || node.OSImage != "Ubuntu 26.04 LTS" || node.Runtime != "containerd://2.2.3" {
		t.Errorf("node: %+v", node)
	}
	web := inventory.Pods[0]
	if web.Name != "web-1" || web.WorkloadKind != "Deployment" || web.Workload != "web" || web.Node != "n1" || web.Phase != "Running" || len(web.Containers) != 1 {
		t.Fatalf("pod: %+v", web)
	}
	if c := web.Containers[0]; c.ID != "c0ffee" || c.Digest != "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || !c.Ready || c.Restarts != 2 || c.State != "running" {
		t.Errorf("container: %+v", c)
	}
	if bare := inventory.Pods[1]; bare.Name != "debug" || bare.Workload != "" {
		t.Errorf("bare pod: %+v", bare)
	}

	withSystem, _ := Scan(context.Background(), client, Options{IncludeSystem: true, Now: now})
	if len(withSystem.Findings) <= len(report.Findings)-4 {
		t.Errorf("--include-system found %d", len(withSystem.Findings))
	}
}

func TestKubeconfigLogins(t *testing.T) {
	server := fakeAPI(t)
	defer server.Close()
	if _, err := Connect(writeKubeconfig(t, server, "      token: secret"), "nope"); err == nil || !strings.Contains(err.Error(), `no context "nope"`) {
		t.Errorf("an unknown context: %v", err)
	}
	if _, err := Connect(writeKubeconfig(t, server, "      token: secret"), "other"); err == nil || !strings.Contains(err.Error(), "no cluster") {
		t.Errorf("a missing cluster: %v", err)
	}
	wrong, _ := Connect(writeKubeconfig(t, server, "      token: wrong"), "")
	if _, err := wrong.ServerVersion(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a wrong token: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	plugin := filepath.Join(t.TempDir(), "login")
	os.WriteFile(plugin, []byte("#!/bin/sh\n[ -n \"$KUBERNETES_EXEC_INFO\" ] || exit 1\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"secret\"}}'\n"), 0o755)
	client, err := Connect(writeKubeconfig(t, server, "      exec:\n        apiVersion: client.authentication.k8s.io/v1\n        command: "+plugin), "")
	if err != nil {
		t.Fatal(err)
	}
	if version, err := client.ServerVersion(context.Background()); err != nil || version.GitVersion != "v1.29.3" {
		t.Errorf("an exec plugin login: %+v %v", version, err)
	}
}

func TestFlagValueAndVersions(t *testing.T) {
	arguments := []string{"kube-apiserver", "--profiling=false", "--audit-log-path", "/var/log/a"}
	if v, ok := flagValue(arguments, "profiling"); !ok || v != "false" {
		t.Error("--name=value")
	}
	if v, ok := flagValue(arguments, "audit-log-path"); !ok || v != "/var/log/a" {
		t.Error("--name value")
	}
	if !newer("1.29.15", "1.29.3") || newer("1.29.3", "1.29.3") || newer("1.29.2", "1.29.10") {
		t.Error("newer")
	}
	for version, provider := range map[string]string{"v1.30.4-eks-a737599": "Amazon EKS", "v1.31.1-gke.1146000": "Google GKE", "v1.31.4+k3s1": "k3s", "v1.31.4": ""} {
		if got := managedProvider(version); got != provider {
			t.Errorf("%s: %q", version, got)
		}
	}
}

func TestRunningDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	for imageID, want := range map[string]string{
		"docker.io/library/nginx@" + digest: digest,
		"docker-pullable://nginx@" + digest: digest,
		digest:                              "", // an image loaded into the node, with no repository
		"ghcr.io/acme/app@sha256:short":     "",
		"":                                  "",
	} {
		if got := runningDigest(imageID); got != want {
			t.Errorf("runningDigest(%q) = %q", imageID, got)
		}
	}
}
