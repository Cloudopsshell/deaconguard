package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"deaconguard/internal/checks"
	"deaconguard/internal/iac"
	"deaconguard/internal/libraries"
	"deaconguard/internal/osv"
)

// Options say what a cluster scan includes.
type Options struct {
	// IncludeSystem checks kube-system, kube-public and kube-node-lease too;
	// their components need privileges by design.
	IncludeSystem bool
	// Releases returns Kubernetes' release lifecycle; nil leaves the
	// version unchecked. CVEs looks up vulnerabilities of a Kubernetes
	// version; nil skips them. Tests replace both.
	Releases func(ctx context.Context) ([]Release, error)
	CVEs     func(ctx context.Context, version string) ([]checks.Finding, error)
	Now      time.Time
}

// Report is what a cluster scan found.
type Report struct {
	Cluster    string `json:"cluster"`
	Server     string `json:"server"`
	Version    string `json:"version"`
	Namespaces int    `json:"namespaces"`
	Nodes      int    `json:"nodes"`
	// Architecture is the nodes' most common CPU architecture, such as amd64.
	Architecture string        `json:"architecture,omitempty"`
	Workloads    int           `json:"workloads"`
	Findings     []iac.Finding `json:"findings"`
	// Images are the images running pods use, for image scans.
	Images []string `json:"images"`
	Notes  []string `json:"notes,omitempty"`
}

var systemNamespaces = map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true}

// kinds are the objects read, with their list paths.
var kinds = []struct{ kind, apiVersion, path string }{
	{"Pod", "v1", "/api/v1/pods"},
	{"Deployment", "apps/v1", "/apis/apps/v1/deployments"},
	{"StatefulSet", "apps/v1", "/apis/apps/v1/statefulsets"},
	{"DaemonSet", "apps/v1", "/apis/apps/v1/daemonsets"},
	{"ReplicaSet", "apps/v1", "/apis/apps/v1/replicasets"},
	{"Job", "batch/v1", "/apis/batch/v1/jobs"},
	{"CronJob", "batch/v1", "/apis/batch/v1/cronjobs"},
	{"ClusterRole", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1/clusterroles"},
	{"ClusterRoleBinding", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
	{"Role", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1/roles"},
	{"RoleBinding", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1/rolebindings"},
}

// object is a listed object: its metadata, and the whole of it for the checks.
type object struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Image   string   `json:"image"`
			Command []string `json:"command"`
			Args    []string `json:"args"`
		} `json:"containers"`
		InitContainers []struct {
			Image string `json:"image"`
		} `json:"initContainers"`
	} `json:"spec"`
}

// Scan reads the cluster and checks it. Only list and get are used.
func Scan(ctx context.Context, client *Client, options Options) (Report, error) {
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	report := Report{Cluster: client.Name, Server: client.Server, Findings: []iac.Finding{}, Images: []string{}}
	version, err := client.ServerVersion(ctx)
	if err != nil {
		return report, err
	}
	report.Version = version.GitVersion
	if nodes, err := client.List(ctx, "/api/v1/nodes"); err == nil {
		architectures := map[string]int{}
		for _, raw := range nodes {
			var node struct {
				Status struct {
					NodeInfo struct {
						Architecture string `json:"architecture"`
					} `json:"nodeInfo"`
				} `json:"status"`
			}
			if json.Unmarshal(raw, &node) == nil {
				report.Nodes++
				architectures[node.Status.NodeInfo.Architecture]++
			}
		}
		for architecture, count := range architectures {
			if count > architectures[report.Architecture] || (count == architectures[report.Architecture] && architecture < report.Architecture) {
				report.Architecture = architecture
			}
		}
	}
	source := func(namespace, kind, name string) string {
		if namespace == "" {
			namespace = "_cluster"
		}
		return "k8s/" + namespace + "/" + strings.ToLower(kind) + "/" + name
	}

	podsIn := map[string]int{}
	images := map[string]bool{}
	var apiServers []object
	skippedSystem := 0
	for _, k := range kinds {
		items, err := client.List(ctx, k.path)
		if errors.Is(err, ErrForbidden) {
			report.Notes = append(report.Notes, fmt.Sprintf("%ss weren't checked: the account may not list them", k.kind))
			continue
		}
		if err != nil {
			return report, err
		}
		for _, raw := range items {
			var meta object
			if err := json.Unmarshal(raw, &meta); err != nil {
				continue
			}
			ns := meta.Metadata.Namespace
			if k.kind == "Pod" {
				if ns == "kube-system" && meta.Metadata.Labels["component"] == "kube-apiserver" {
					apiServers = append(apiServers, meta)
				}
				if !systemNamespaces[ns] {
					podsIn[ns]++
				}
				for _, c := range meta.Spec.Containers {
					images[c.Image] = true
				}
				for _, c := range meta.Spec.InitContainers {
					images[c.Image] = true
				}
			}
			// A controller's pods and ReplicaSets are checked through it.
			if len(meta.Metadata.OwnerReferences) > 0 && (k.kind == "Pod" || k.kind == "ReplicaSet" || k.kind == "Job") {
				continue
			}
			// Kubernetes' own roles and bindings: the API server's defaults,
			// and kubeadm's.
			builtIn := meta.Metadata.Labels["kubernetes.io/bootstrapping"] == "rbac-defaults" ||
				strings.HasPrefix(meta.Metadata.Name, "system:") || strings.HasPrefix(meta.Metadata.Name, "kubeadm:")
			if !options.IncludeSystem && (systemNamespaces[ns] || builtIn) {
				skippedSystem++
				continue
			}
			var node yaml.Node
			if err := yaml.Unmarshal(raw, &node); err != nil || len(node.Content) == 0 {
				continue
			}
			root := node.Content[0]
			// List items leave out kind and apiVersion.
			setField(root, "kind", k.kind)
			setField(root, "apiVersion", k.apiVersion)
			if k.kind != "ClusterRole" && k.kind != "ClusterRoleBinding" && k.kind != "Role" && k.kind != "RoleBinding" {
				report.Workloads++
			}
			report.Findings = append(report.Findings, iac.CheckObject(source(ns, k.kind, meta.Metadata.Name), root)...)
		}
	}
	for image := range images {
		report.Images = append(report.Images, image)
	}
	sort.Strings(report.Images)
	if skippedSystem > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf("%d objects of Kubernetes itself (kube-system, built-in roles) were left out: its components need privileges by design", skippedSystem))
	}

	report.Findings = append(report.Findings, checkNamespaces(ctx, client, podsIn, options, &report)...)
	report.Findings = append(report.Findings, checkAPIServers(apiServers, &report)...)
	report.Findings = append(report.Findings, checkVersion(ctx, version, options, &report)...)

	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
		}
		return a.File < b.File
	})
	return report, nil
}

func rank(severity string) int {
	return map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[strings.ToUpper(severity)]
}

// setField sets key in a mapping node to a string, replacing any value.
func setField(node *yaml.Node, key, value string) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			node.Content[index+1] = &yaml.Node{Kind: yaml.ScalarNode, Value: value}
			return
		}
	}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Value: value})
}

// checkNamespaces finds namespaces with pods but no NetworkPolicy, or no
// enforced Pod Security Standard.
func checkNamespaces(ctx context.Context, client *Client, podsIn map[string]int, options Options, report *Report) []iac.Finding {
	var findings []iac.Finding
	namespaces, err := client.List(ctx, "/api/v1/namespaces")
	if err != nil {
		report.Notes = append(report.Notes, "Namespaces weren't checked: "+err.Error())
		return nil
	}
	policies, err := client.List(ctx, "/apis/networking.k8s.io/v1/networkpolicies")
	policyIn := map[string]bool{}
	if err != nil {
		report.Notes = append(report.Notes, "NetworkPolicies weren't checked: "+err.Error())
	}
	for _, raw := range policies {
		var meta object
		if json.Unmarshal(raw, &meta) == nil {
			policyIn[meta.Metadata.Namespace] = true
		}
	}
	for _, raw := range namespaces {
		var meta object
		if json.Unmarshal(raw, &meta) != nil {
			continue
		}
		name := meta.Metadata.Name
		report.Namespaces++
		if podsIn[name] == 0 || systemNamespaces[name] {
			continue
		}
		file := "k8s/" + name + "/namespace/" + name
		if err == nil && !policyIn[name] {
			findings = append(findings, iac.NewFinding("DG-K8S-030", file, 1,
				fmt.Sprintf("Namespace %s: %d pods and no NetworkPolicy", name, podsIn[name]),
				"Without a NetworkPolicy, any pod in the cluster can reach these pods, and they can reach anything. Add a default-deny policy, then allow the traffic each workload needs. It needs a network plugin that enforces policies, such as Calico or Cilium."))
		}
		if level := meta.Metadata.Labels["pod-security.kubernetes.io/enforce"]; level == "" || level == "privileged" {
			findings = append(findings, iac.NewFinding("DG-K8S-031", file, 1,
				fmt.Sprintf("Namespace %s: no Pod Security Standard is enforced", name),
				"Label the namespace pod-security.kubernetes.io/enforce=baseline (or restricted), so Kubernetes refuses privileged pods there. Try it first with the warn label."))
		}
	}
	return findings
}

// flagValue reads --name=value or --name value from a command line.
func flagValue(arguments []string, name string) (string, bool) {
	for index, argument := range arguments {
		if value, ok := strings.CutPrefix(argument, "--"+name+"="); ok {
			return value, true
		}
		if argument == "--"+name && index+1 < len(arguments) {
			return arguments[index+1], true
		}
	}
	return "", false
}

// checkAPIServers checks the API server's flags, where it runs as a pod, as
// kubeadm sets it up. Managed and embedded control planes (EKS, GKE, AKS,
// k3s) don't show them.
func checkAPIServers(servers []object, report *Report) []iac.Finding {
	if len(servers) == 0 {
		report.Notes = append(report.Notes, "The API server's settings aren't visible (a managed or embedded control plane, such as EKS, GKE, AKS or k3s): check them with your provider")
		return nil
	}
	var findings []iac.Finding
	seen := map[string]bool{}
	add := func(id, title, detail string) {
		if !seen[id] {
			seen[id] = true
			findings = append(findings, iac.NewFinding(id, "k8s/kube-system/pod/"+servers[0].Metadata.Name, 1, title, detail))
		}
	}
	for _, server := range servers {
		for _, container := range server.Spec.Containers {
			arguments := append(append([]string{}, container.Command...), container.Args...)
			if mode, _ := flagValue(arguments, "authorization-mode"); strings.Contains(mode, "AlwaysAllow") {
				add("DG-K8S-040", "The API server allows every request: --authorization-mode="+mode,
					"Use --authorization-mode=Node,RBAC, so requests are checked against roles.")
			}
			if anonymous, _ := flagValue(arguments, "anonymous-auth"); anonymous != "false" {
				add("DG-K8S-041", "The API server accepts anonymous requests (--anonymous-auth isn't false)",
					"Set --anonymous-auth=false, or limit anonymous access to the health endpoints with an AuthenticationConfiguration.")
			}
			if _, ok := flagValue(arguments, "audit-log-path"); !ok {
				if _, webhook := flagValue(arguments, "audit-webhook-config-file"); !webhook {
					add("DG-K8S-042", "The API server keeps no audit log",
						"Set --audit-policy-file and --audit-log-path (or an audit webhook), so who did what in the cluster is recorded.")
				}
			}
			if _, ok := flagValue(arguments, "encryption-provider-config"); !ok {
				add("DG-K8S-043", "Secrets aren't encrypted at rest",
					"Set --encryption-provider-config with an aescbc, secretbox or KMS provider, so etcd backups and disks don't hold secrets in plain text.")
			}
			if profiling, _ := flagValue(arguments, "profiling"); profiling != "false" {
				add("DG-K8S-044", "The API server's profiling endpoint is on",
					"Set --profiling=false; profiling data shows how the server works, and nobody needs it in production.")
			}
		}
	}
	return findings
}

// Release is a Kubernetes minor release's support.
type Release struct {
	Cycle  string `json:"cycle"`
	EOL    string `json:"eol"`
	Latest string `json:"latest"`
}

var versionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// managedProvider names a provider whose builds have their own support.
func managedProvider(gitVersion string) string {
	switch {
	case strings.Contains(gitVersion, "-eks"):
		return "Amazon EKS"
	case strings.Contains(gitVersion, "-gke"):
		return "Google GKE"
	case strings.Contains(gitVersion, "+rke2"):
		return "RKE2"
	case strings.Contains(gitVersion, "+k3s"):
		return "k3s"
	}
	return ""
}

// VersionFindings checks a Kubernetes version's support and known CVEs, as
// Scan does, for a server that adds them to an agent's report.
func VersionFindings(ctx context.Context, gitVersion string, options Options) ([]iac.Finding, []string) {
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	var report Report
	findings := checkVersion(ctx, Version{GitVersion: gitVersion}, options, &report)
	return findings, report.Notes
}

// checkVersion checks the Kubernetes version's support and known CVEs.
func checkVersion(ctx context.Context, version Version, options Options, report *Report) []iac.Finding {
	match := versionPattern.FindStringSubmatch(version.GitVersion)
	if match == nil {
		report.Notes = append(report.Notes, "The Kubernetes version "+version.GitVersion+" wasn't understood")
		return nil
	}
	cycle, plain := match[1]+"."+match[2], match[1]+"."+match[2]+"."+match[3]
	file := "k8s/_cluster/version/" + plain
	var findings []iac.Finding
	provider := managedProvider(version.GitVersion)
	if options.Releases != nil {
		releases, err := options.Releases(ctx)
		if err != nil {
			report.Notes = append(report.Notes, "Kubernetes' release support wasn't checked: "+err.Error())
		}
		for _, release := range releases {
			if release.Cycle != cycle {
				continue
			}
			if release.EOL != "" && release.EOL <= options.Now.UTC().Format("2006-01-02") {
				detail := fmt.Sprintf("Kubernetes %s stopped getting security fixes on %s. Upgrade to a supported minor release.", cycle, release.EOL)
				if provider == "Amazon EKS" || provider == "Google GKE" {
					detail += " " + provider + " supports versions longer than upstream, sometimes at extra cost; check its calendar."
				}
				findings = append(findings, iac.NewFinding("DG-K8S-032", file, 1, fmt.Sprintf("Kubernetes %s is past its end of life (%s)", plain, release.EOL), detail))
			}
			if newer(release.Latest, plain) {
				findings = append(findings, iac.NewFinding("DG-K8S-033", file, 1,
					fmt.Sprintf("Kubernetes %s is behind the latest %s patch, %s", plain, cycle, release.Latest),
					"Patch releases fix security issues and bugs without changing behaviour. Upgrade the control plane, then the nodes."))
			}
		}
	}
	if options.CVEs != nil {
		vulnerabilities, err := options.CVEs(ctx, plain)
		if err != nil {
			report.Notes = append(report.Notes, "Kubernetes' own vulnerabilities weren't checked: "+err.Error())
		}
		for _, v := range vulnerabilities {
			findings = append(findings, iac.Finding{Rule: v.Rule, Severity: strings.ToUpper(v.Severity), File: file, Line: 1,
				Title: "Kubernetes " + plain + ": " + strings.TrimPrefix(v.Title, "k8s.io/kubernetes "+plain+" (Go): "), Detail: v.Detail})
		}
		if provider != "" && len(vulnerabilities) > 0 {
			report.Notes = append(report.Notes, provider+" builds may carry fixes for Kubernetes vulnerabilities before upstream versions do; check the provider's security bulletins for those listed")
		}
	}
	return findings
}

// newer reports whether version a is newer than b, both x.y.z.
func newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for index := 0; index < 3 && index < len(pa) && index < len(pb); index++ {
		x, _ := strconv.Atoi(pa[index])
		y, _ := strconv.Atoi(pb[index])
		if x != y {
			return x > y
		}
	}
	return false
}

// OnlineReleases reads Kubernetes' release support from endoflife.date.
func OnlineReleases(ctx context.Context) ([]Release, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://endoflife.date/api/kubernetes.json", nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife.date answered %s", response.Status)
	}
	var releases []Release
	err = json.NewDecoder(response.Body).Decode(&releases)
	return releases, err
}

// OnlineCVEs looks up a Kubernetes version's vulnerabilities in OSV, as the
// Go module k8s.io/kubernetes: only the version is sent.
func OnlineCVEs(ctx context.Context, version string) ([]checks.Finding, error) {
	result := checks.Result{Status: checks.StatusCompleted, Libraries: &libraries.Result{
		Libraries: []libraries.Library{{Ecosystem: "Go", Name: "k8s.io/kubernetes", Version: version}},
	}}
	osv.Evaluate(&result, osv.NewClient(), &http.Client{Timeout: 60 * time.Second}, time.Now().UTC())
	if result.Status == checks.StatusFailed {
		return nil, errors.New(result.Error)
	}
	return result.Findings, nil
}
