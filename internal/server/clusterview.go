package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"deaconguard/internal/checks"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

// A Kubernetes cluster is one host on the dashboard, with what it runs
// beneath it: its nodes, and its namespaces, their workloads, pods and
// containers. The view is put together from the cluster agent's latest
// scan, which lists them, the findings of that scan, which name the object
// they are about, and the latest scans of the node agents, whose Running
// containers check found each container's vulnerabilities and whose malware
// checks found files containers wrote. Containers are matched by the ID the
// runtime gave them, which both agents report.

// viewCounts are the problems in a part of the cluster: vulnerabilities by
// severity, findings about settings (misconfigurations), and malware.
type viewCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Fixable  int `json:"fixable"`
	Settings int `json:"settings"`
	Malware  int `json:"malware"`
}

func (counts *viewCounts) add(other viewCounts) {
	counts.Critical += other.Critical
	counts.High += other.High
	counts.Medium += other.Medium
	counts.Low += other.Low
	counts.Fixable += other.Fixable
	counts.Settings += other.Settings
	counts.Malware += other.Malware
}

func (counts *viewCounts) addSeverity(severity string, n int) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		counts.Critical += n
	case "HIGH":
		counts.High += n
	case "MEDIUM":
		counts.Medium += n
	case "LOW":
		counts.Low += n
	}
}

type clusterView struct {
	Cluster      store.HostSummary `json:"cluster"`
	ScanID       string            `json:"scan_id,omitempty"`
	ScannedAt    string            `json:"scanned_at,omitempty"`
	Version      string            `json:"version,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	// Inventory is false until a cluster agent of 1.21.0 or later has
	// scanned the cluster: older ones don't list what it runs.
	Inventory   bool             `json:"inventory"`
	Counts      viewCounts       `json:"counts"`
	Pods        int              `json:"pods"`
	Containers  int              `json:"containers"`
	PodsLeftOut int              `json:"pods_left_out,omitempty"`
	Nodes       []nodeView       `json:"nodes"`
	Namespaces  []namespaceView  `json:"namespaces"`
	Findings    []checks.Finding `json:"findings"`
	Images      []imageView      `json:"images"`
	Notes       []string         `json:"notes"`
}

type nodeView struct {
	checks.ClusterNode
	Pods int `json:"pods"`
	// Host is the node's own host, when a node agent runs on it.
	Host   *store.HostSummary `json:"host,omitempty"`
	Counts viewCounts         `json:"counts"`
}

type namespaceView struct {
	Name      string           `json:"name"`
	System    bool             `json:"system"`
	Counts    viewCounts       `json:"counts"`
	Pods      int              `json:"pods"`
	Findings  []checks.Finding `json:"findings"`
	Workloads []workloadView   `json:"workloads"`
}

type workloadView struct {
	Kind     string           `json:"kind"`
	Name     string           `json:"name"`
	Counts   viewCounts       `json:"counts"`
	Findings []checks.Finding `json:"findings"`
	Pods     []podView        `json:"pods"`
}

type podView struct {
	Name       string          `json:"name"`
	Node       string          `json:"node,omitempty"`
	NodeHostID string          `json:"node_host_id,omitempty"`
	Phase      string          `json:"phase,omitempty"`
	Restarts   int             `json:"restarts"`
	Counts     viewCounts      `json:"counts"`
	Containers []containerView `json:"containers"`
}

type containerView struct {
	checks.ClusterContainer
	// Checked says where its vulnerabilities come from: "node", the node
	// agent's Running containers check of this very container; "image", the
	// server's check of its image; empty when neither has run.
	Checked string           `json:"checked,omitempty"`
	Counts  viewCounts       `json:"counts"`
	Malware []checks.Finding `json:"malware,omitempty"`
}

type imageView struct {
	checks.RunningImage
	Checked string     `json:"checked,omitempty"`
	Counts  viewCounts `json:"counts"`
}

// nodeResults is what a node's latest scans say about its containers, by
// container ID.
type nodeResults struct {
	containers map[string]checks.ContainerResult
	malware    map[string][]checks.Finding
	// byName are malware findings of agents before 1.21.0, which name the
	// container but not its ID.
	byName map[string][]checks.Finding
}

// nodeResultsCache keeps what was read of a node's scans, by the scans' IDs,
// so the view doesn't read every node's reports again on each visit.
type nodeResultsCache struct {
	mu      sync.Mutex
	entries map[string]*nodeResults
}

const maxNodeResults = 200

func (c *nodeResultsCache) get(key string, read func() *nodeResults) *nodeResults {
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.mu.Unlock()
		return entry
	}
	c.mu.Unlock()
	entry := read()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= maxNodeResults {
		c.entries = map[string]*nodeResults{}
	}
	c.entries[key] = entry
	return entry
}

var nodeCache nodeResultsCache

// checkResults reads a stored report's results of one check.
func checkResults(scanID, check string) (checks.Result, bool) {
	report, err := store.GetFullReport(scanID)
	if err != nil {
		return checks.Result{}, false
	}
	raw, ok := report["check_results"]
	if !ok {
		return checks.Result{}, false
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return checks.Result{}, false
	}
	var results map[string]json.RawMessage
	if json.Unmarshal(encoded, &results) != nil || results[check] == nil {
		return checks.Result{}, false
	}
	var result checks.Result
	if json.Unmarshal(results[check], &result) != nil {
		return checks.Result{}, false
	}
	return result, true
}

func readNodeResults(host store.HostSummary) *nodeResults {
	key := host.ID
	for _, check := range []string{checks.Containers, checks.Malware, checks.Antivirus} {
		key += "/" + host.Checks[check].ScanID
	}
	return nodeCache.get(key, func() *nodeResults {
		results := &nodeResults{containers: map[string]checks.ContainerResult{}, malware: map[string][]checks.Finding{}, byName: map[string][]checks.Finding{}}
		if summary, ok := host.Checks[checks.Containers]; ok {
			if result, ok := checkResults(summary.ScanID, checks.Containers); ok {
				for _, container := range result.Containers {
					// The inventory is what the agent read; the view needs only
					// the counts.
					container.Inventory, container.Findings, container.Vulnerabilities = nil, nil, nil
					results.containers[container.ID] = container
				}
			}
		}
		for _, check := range []string{checks.Malware, checks.Antivirus} {
			summary, ok := host.Checks[check]
			if !ok {
				continue
			}
			result, ok := checkResults(summary.ScanID, check)
			if !ok {
				continue
			}
			for _, finding := range result.Findings {
				switch {
				case finding.ContainerID != "":
					results.malware[finding.ContainerID] = append(results.malware[finding.ContainerID], finding)
				case finding.Container != "":
					results.byName[finding.Container] = append(results.byName[finding.Container], finding)
				}
			}
		}
		return results
	})
}

// container finds a container's result by its ID, which runtimes report in
// full or shortened.
func (results *nodeResults) container(id string) (checks.ContainerResult, bool) {
	if id == "" {
		return checks.ContainerResult{}, false
	}
	if result, ok := results.containers[id]; ok {
		return result, true
	}
	for key, result := range results.containers {
		if len(key) >= 12 && (strings.HasPrefix(id, key) || strings.HasPrefix(key, id)) {
			return result, true
		}
	}
	return checks.ContainerResult{}, false
}

func (results *nodeResults) malwareIn(id, name string, unique bool) []checks.Finding {
	if id != "" {
		for key, findings := range results.malware {
			if key == id || (len(key) >= 12 && (strings.HasPrefix(id, key) || strings.HasPrefix(key, id))) {
				return findings
			}
		}
	}
	if unique {
		return results.byName[name]
	}
	return nil
}

// findingObject reads the namespace, kind and name a cluster finding is
// about from its evidence, k8s/NAMESPACE/KIND/NAME; the namespace is
// _cluster for objects of the whole cluster.
func findingObject(finding checks.Finding) (namespace, kind, name string, ok bool) {
	parts := strings.SplitN(finding.Evidence, "/", 4)
	if len(parts) != 4 || parts[0] != "k8s" {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

// kindNames turns the lowercase kinds in findings' evidence back into
// Kubernetes' names.
var kindNames = map[string]string{
	"pod": "Pod", "deployment": "Deployment", "statefulset": "StatefulSet", "daemonset": "DaemonSet", "replicaset": "ReplicaSet",
	"job": "Job", "cronjob": "CronJob",
}

func (s *Server) clusterView(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hosts, err := store.HostSummaries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var cluster *store.HostSummary
	for index := range hosts {
		if hosts[index].ID == id {
			cluster = &hosts[index]
		}
	}
	if cluster == nil || !cluster.IsCluster() {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown cluster: %s", id))
		return
	}
	writeJSON(w, http.StatusOK, buildClusterView(*cluster, hosts, s.agents.clusterImages))
}

// buildClusterView puts a cluster's view together; images is the server's
// cache of the images clusters run, nil in tests that don't need it.
func buildClusterView(cluster store.HostSummary, hosts []store.HostSummary, images scan.ClusterImages) clusterView {
	view := clusterView{Cluster: cluster, Nodes: []nodeView{}, Namespaces: []namespaceView{}, Findings: []checks.Finding{}, Images: []imageView{}, Notes: []string{}}
	summary, scanned := cluster.Checks[checks.Kubernetes]
	if !scanned {
		return view
	}
	result, ok := checkResults(summary.ScanID, checks.Kubernetes)
	if !ok || result.Cluster == nil {
		return view
	}
	view.ScanID, view.ScannedAt = summary.ScanID, summary.ScannedAt
	view.Version, view.Architecture = result.Cluster.Version, result.Cluster.Architecture
	inventory := result.Cluster.Inventory
	view.Inventory = inventory != nil
	if inventory == nil {
		inventory = &checks.ClusterInventory{}
		view.Notes = append(view.Notes, "The cluster agent is older than 1.21.0, so it doesn't list the cluster's namespaces, pods and nodes. Upgrade it, then scan the cluster.")
	}
	view.PodsLeftOut = inventory.PodsLeftOut

	// The node agents' hosts, by node name.
	nodeHosts := map[string]store.HostSummary{}
	for _, host := range hosts {
		if host.ClusterID == cluster.ID {
			nodeHosts[host.Address] = host
			if host.Hostname != "" {
				nodeHosts[host.Hostname] = host
			}
		}
	}
	results := map[string]*nodeResults{}
	resultsFor := func(node string) *nodeResults {
		host, ok := nodeHosts[node]
		if !ok {
			return nil
		}
		if _, read := results[node]; !read {
			results[node] = readNodeResults(host)
		}
		return results[node]
	}

	// Findings about workloads, namespaces and the cluster itself.
	platform := "linux/amd64"
	if view.Architecture != "" {
		platform = "linux/" + view.Architecture
	}
	type objectKey struct{ namespace, kind, name string }
	objectFindings := map[objectKey][]checks.Finding{}
	for _, finding := range result.Findings {
		if finding.Rule == "DG-K8S-050" {
			// The images' vulnerabilities, which the containers show.
			continue
		}
		namespace, kind, name, ok := findingObject(finding)
		if !ok || namespace == "_cluster" {
			view.Findings = append(view.Findings, finding)
			continue
		}
		objectFindings[objectKey{namespace, kind, name}] = append(objectFindings[objectKey{namespace, kind, name}], finding)
	}

	// Images: the node agents' check of each container when there is one,
	// else the server's check of its image.
	imageCounts := func(image checks.RunningImage) (viewCounts, string) {
		var counts viewCounts
		if images == nil {
			return counts, ""
		}
		found, failure, ok := images.Cached(image, platform)
		if !ok || failure != nil {
			return counts, ""
		}
		for severity, n := range found.FixableSeverity {
			counts.addSeverity(severity, n)
		}
		counts.Fixable = found.Fixable
		return counts, "image"
	}

	namespaces := map[string]*namespaceView{}
	namespaceOf := func(name string) *namespaceView {
		if namespaces[name] == nil {
			namespaces[name] = &namespaceView{Name: name, System: name == "kube-system" || name == "kube-public" || name == "kube-node-lease",
				Findings: []checks.Finding{}, Workloads: []workloadView{}}
		}
		return namespaces[name]
	}
	for _, name := range inventory.Namespaces {
		namespaceOf(name)
	}
	type workloadKey struct{ namespace, kind, name string }
	workloads := map[workloadKey]*workloadView{}
	workloadOf := func(namespace, kind, name string) *workloadView {
		key := workloadKey{namespace, kind, name}
		if workloads[key] == nil {
			workloads[key] = &workloadView{Kind: kind, Name: name, Findings: []checks.Finding{}, Pods: []podView{}}
		}
		return workloads[key]
	}
	podsOnNode := map[string]int{}
	nodeCounts := map[string]*viewCounts{}
	imageRows := map[string]*imageView{}
	for _, pod := range inventory.Pods {
		kind, name := pod.WorkloadKind, pod.Workload
		if name == "" {
			kind, name = "Pod", pod.Name
		}
		view.Pods++
		podsOnNode[pod.Node]++
		node := resultsFor(pod.Node)
		row := podView{Name: pod.Name, Node: pod.Node, Phase: pod.Phase, Containers: []containerView{}}
		if host, ok := nodeHosts[pod.Node]; ok {
			row.NodeHostID = host.ID
		}
		names := map[string]int{}
		for _, container := range pod.Containers {
			names[container.Name]++
		}
		for _, container := range pod.Containers {
			view.Containers++
			row.Restarts += container.Restarts
			item := containerView{ClusterContainer: container}
			if node != nil {
				if found, ok := node.container(container.ID); ok && found.Scanned() && found.Severity != nil {
					for severity, n := range found.Severity {
						item.Counts.addSeverity(severity, n)
					}
					item.Counts.Fixable = found.Fixable
					item.Checked = "node"
				}
				// A name alone identifies a container only for agents before
				// 1.21.0, when no other container on the node has it.
				item.Malware = node.malwareIn(container.ID, container.Name, len(node.byName[container.Name]) > 0 && names[container.Name] == 1)
				item.Counts.Malware = len(item.Malware)
			}
			running := checks.RunningImage{Image: container.Image, Digest: container.Digest}
			if item.Checked == "" {
				counts, checked := imageCounts(running)
				counts.Malware = item.Counts.Malware
				item.Counts, item.Checked = counts, checked
			}
			row.Counts.add(item.Counts)
			row.Containers = append(row.Containers, item)
			key := container.Image + "@" + container.Digest
			if imageRows[key] == nil {
				imageRows[key] = &imageView{RunningImage: checks.RunningImage{Image: container.Image, Digest: container.Digest}, Checked: item.Checked}
				imageRows[key].Counts = item.Counts
				imageRows[key].Counts.Malware = 0
			}
			image := imageRows[key]
			image.Pods++
			if !contains(image.Namespaces, pod.Namespace) {
				image.Namespaces = append(image.Namespaces, pod.Namespace)
			}
		}
		if nodeCounts[pod.Node] == nil {
			nodeCounts[pod.Node] = &viewCounts{}
		}
		nodeCounts[pod.Node].Malware += row.Counts.Malware
		workload := workloadOf(pod.Namespace, kind, name)
		workload.Pods = append(workload.Pods, row)
		workload.Counts.add(row.Counts)
		namespaceOf(pod.Namespace).Pods++
	}
	// Workloads without pods that findings name, such as a CronJob between
	// runs, and findings about namespaces and their roles.
	for key, findings := range objectFindings {
		var counts viewCounts
		counts.Settings = len(findings)
		if kind, ok := kindNames[key.kind]; ok {
			workload := workloadOf(key.namespace, kind, key.name)
			workload.Findings = append(workload.Findings, findings...)
			workload.Counts.add(counts)
			continue
		}
		namespace := namespaceOf(key.namespace)
		namespace.Findings = append(namespace.Findings, findings...)
		namespace.Counts.add(counts)
	}
	for key, workload := range workloads {
		sort.Slice(workload.Pods, func(i, j int) bool { return workload.Pods[i].Name < workload.Pods[j].Name })
		sortFindings(workload.Findings)
		namespace := namespaceOf(key.namespace)
		namespace.Workloads = append(namespace.Workloads, *workload)
		namespace.Counts.add(workload.Counts)
	}
	for _, namespace := range namespaces {
		sort.Slice(namespace.Workloads, func(i, j int) bool {
			a, b := namespace.Workloads[i], namespace.Workloads[j]
			if problems(a.Counts) != problems(b.Counts) {
				return problems(a.Counts) > problems(b.Counts)
			}
			return a.Kind+"/"+a.Name < b.Kind+"/"+b.Name
		})
		sortFindings(namespace.Findings)
		view.Counts.add(namespace.Counts)
		view.Namespaces = append(view.Namespaces, *namespace)
	}
	sort.Slice(view.Namespaces, func(i, j int) bool {
		a, b := view.Namespaces[i], view.Namespaces[j]
		if a.System != b.System {
			return !a.System
		}
		if problems(a.Counts) != problems(b.Counts) {
			return problems(a.Counts) > problems(b.Counts)
		}
		return a.Name < b.Name
	})
	view.Counts.Settings += len(view.Findings)

	for _, node := range inventory.Nodes {
		row := nodeView{ClusterNode: node, Pods: podsOnNode[node.Name]}
		if host, ok := nodeHosts[node.Name]; ok {
			host := host
			row.Host = &host
			if packages, ok := host.Checks[checks.Packages]; ok {
				row.Counts.Critical, row.Counts.High = packages.Severity.Critical, packages.Severity.High
				row.Counts.Medium, row.Counts.Low = packages.Severity.Medium, packages.Severity.Low
			}
			for _, check := range []string{checks.Malware, checks.Antivirus} {
				if found, ok := host.Checks[check]; ok {
					row.Counts.Malware += found.FindingCount
				}
			}
		}
		view.Nodes = append(view.Nodes, row)
	}
	missing := 0
	for _, node := range view.Nodes {
		if node.Host == nil {
			missing++
		}
	}
	if missing > 0 && len(view.Nodes) > 0 {
		view.Notes = append(view.Notes, fmt.Sprintf("%d of %d nodes have no node agent: their packages and malware aren't checked, and their containers are checked only through their images. Turn on agent.enabled in the Helm chart.", missing, len(view.Nodes)))
	}
	for _, image := range imageRows {
		sort.Strings(image.Namespaces)
		view.Images = append(view.Images, *image)
	}
	sort.Slice(view.Images, func(i, j int) bool {
		a, b := view.Images[i], view.Images[j]
		if problems(a.Counts) != problems(b.Counts) {
			return problems(a.Counts) > problems(b.Counts)
		}
		return a.Image < b.Image
	})
	return view
}

// problems weighs counts, to list the worst first.
func problems(counts viewCounts) int {
	return counts.Malware*100000 + counts.Critical*10000 + counts.High*100 + counts.Settings*10 + counts.Medium
}

func sortFindings(findings []checks.Finding) {
	rank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	sort.SliceStable(findings, func(i, j int) bool {
		return rank[strings.ToUpper(findings[i].Severity)] > rank[strings.ToUpper(findings[j].Severity)]
	})
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// linkClusterNodes records a cluster's nodes from its scan, so their hosts
// are shown under it.
func linkClusterNodes(host store.Host, report map[string]any) {
	if !host.IsCluster() {
		return
	}
	encoded, err := json.Marshal(report["check_results"])
	if err != nil {
		return
	}
	var results map[string]checks.Result
	if json.Unmarshal(encoded, &results) != nil {
		return
	}
	result, ok := results[checks.Kubernetes]
	if !ok || result.Cluster == nil || result.Cluster.Inventory == nil {
		return
	}
	names := make([]string, 0, len(result.Cluster.Inventory.Nodes))
	for _, node := range result.Cluster.Inventory.Nodes {
		names = append(names, node.Name)
	}
	if err := store.LinkClusterNodes(host.ID, names); err != nil {
		serverLog(host.ID, store.LogError, "Could not link %s's nodes to it: %v", host.Address, err)
	}
}
