package iac

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	pssBaseline   = "Kubernetes Pod Security Standards (baseline)"
	pssRestricted = "Kubernetes Pod Security Standards (restricted)"
	nsaGuide      = "NSA/CISA Kubernetes Hardening Guide"
	rbacSource    = "Kubernetes RBAC good practices"
)

var kubernetesRules = []Rule{
	{ID: "DG-K8S-001", Severity: "CRITICAL", Title: "A container is privileged", Source: pssBaseline},
	{ID: "DG-K8S-002", Severity: "HIGH", Title: "The pod shares the node's network, process or IPC namespace", Source: pssBaseline},
	{ID: "DG-K8S-003", Severity: "HIGH", Title: "The pod mounts a folder of the node (hostPath)", Source: pssBaseline},
	{ID: "DG-K8S-004", Severity: "HIGH", Title: "A container adds a dangerous Linux capability", Source: pssBaseline},
	{ID: "DG-K8S-005", Severity: "MEDIUM", Title: "A container uses a port on the node (hostPort)", Source: pssBaseline},
	{ID: "DG-K8S-006", Severity: "HIGH", Title: "A container turns off seccomp, AppArmor or /proc masking", Source: pssBaseline},
	{ID: "DG-K8S-007", Severity: "MEDIUM", Title: "A container may gain more privileges than its process has", Source: pssRestricted},
	{ID: "DG-K8S-008", Severity: "MEDIUM", Title: "A container may run as root", Source: pssRestricted},
	{ID: "DG-K8S-009", Severity: "HIGH", Title: "A container runs as root (runAsUser: 0)", Source: pssRestricted},
	{ID: "DG-K8S-010", Severity: "LOW", Title: "A container keeps Linux capabilities it doesn't drop", Source: pssRestricted},
	{ID: "DG-K8S-011", Severity: "LOW", Title: "No seccomp profile is set", Source: pssRestricted},
	{ID: "DG-K8S-012", Severity: "LOW", Title: "A container's root file system is writable", Source: nsaGuide},
	{ID: "DG-K8S-013", Severity: "LOW", Title: "A container has no memory limit", Source: nsaGuide},
	{ID: "DG-K8S-014", Severity: "MEDIUM", Title: "A container image isn't pinned to a version", Source: nsaGuide},
	{ID: "DG-K8S-015", Severity: "HIGH", Title: "A secret is written into the manifest", Source: nsaGuide},
	{ID: "DG-K8S-016", Severity: "LOW", Title: "The pod gets a service account token it may not need", Source: nsaGuide},
	{ID: "DG-K8S-020", Severity: "HIGH", Title: "A binding grants cluster-admin", Source: rbacSource},
	{ID: "DG-K8S-021", Severity: "HIGH", Title: "A role grants every action on every resource", Source: rbacSource},
	{ID: "DG-K8S-022", Severity: "MEDIUM", Title: "A role can read secrets", Source: rbacSource},
	{ID: "DG-K8S-023", Severity: "HIGH", Title: "A role can escalate privileges", Source: rbacSource},
	// Live clusters only (deaconguard kube scan).
	{ID: "DG-K8S-030", Severity: "MEDIUM", Title: "A namespace has no NetworkPolicy: its pods accept traffic from anywhere", Source: nsaGuide},
	{ID: "DG-K8S-031", Severity: "LOW", Title: "A namespace doesn't enforce a Pod Security Standard", Source: pssBaseline},
	{ID: "DG-K8S-032", Severity: "HIGH", Title: "The Kubernetes version gets no more security fixes", Source: kubeReleases},
	{ID: "DG-K8S-033", Severity: "LOW", Title: "The Kubernetes version is behind its latest patch release", Source: kubeReleases},
	{ID: "DG-K8S-040", Severity: "CRITICAL", Title: "The API server allows every request (AlwaysAllow)", Source: nsaGuide},
	{ID: "DG-K8S-041", Severity: "MEDIUM", Title: "The API server accepts anonymous requests", Source: nsaGuide},
	{ID: "DG-K8S-042", Severity: "MEDIUM", Title: "The API server keeps no audit log", Source: nsaGuide},
	{ID: "DG-K8S-043", Severity: "MEDIUM", Title: "Secrets aren't encrypted at rest", Source: nsaGuide},
	{ID: "DG-K8S-044", Severity: "LOW", Title: "The API server's profiling endpoint is on", Source: nsaGuide},
	{ID: "DG-K8S-050", Severity: "HIGH", Title: "A running image has vulnerabilities a newer build fixes", Source: nsaGuide},
	{ID: "DG-K8S-034", Severity: "MEDIUM", Title: "Workloads run in the default namespace", Source: stigSource},
	{ID: "DG-K8S-045", Severity: "MEDIUM", Title: "The Kubernetes dashboard is installed", Source: stigSource},
}

const stigSource = "DISA Kubernetes STIG"

// kubernetesSTIG maps rules to the DISA Kubernetes STIG (V2R6, April 2026)
// rules they check. Only rules that check the same thing are mapped.
var kubernetesSTIG = map[string][]string{
	"DG-K8S-005": {"V-242414"}, // non-privileged host ports for user pods
	"DG-K8S-015": {"V-274883"}, // sensitive information stored in Secrets
	"DG-K8S-022": {"V-274884"}, // Secret access on a need-to-know basis
	"DG-K8S-031": {"V-242437"}, // a pod security policy set
	"DG-K8S-032": {"V-242443"}, // the latest updates
	"DG-K8S-033": {"V-242443"},
	"DG-K8S-034": {"V-242383"},             // user-managed resources in dedicated namespaces
	"DG-K8S-040": {"V-242382"},             // Node,RBAC authorization mode
	"DG-K8S-041": {"V-242390"},             // anonymous authentication disabled
	"DG-K8S-042": {"V-242402", "V-242461"}, // audit log path; audit logs enabled
	"DG-K8S-043": {"V-274882"},             // Secrets encrypted at rest
	"DG-K8S-045": {"V-242395"},             // the dashboard not enabled
}

// KubernetesVulnerabilitySTIG is the STIG rule Kubernetes' own known
// vulnerabilities fail: the latest updates (V-242443).
var KubernetesVulnerabilitySTIG = []string{"V-242443"}

const kubeReleases = "Kubernetes release support (kubernetes.io/releases)"

// CheckObject checks one Kubernetes object, such as one read from a live
// cluster; file says where it came from.
func CheckObject(file string, object *yaml.Node) []Finding { return checkObject(file, object) }

// NewFinding makes a finding of a rule, for checks outside this package.
func NewFinding(id, file string, line int, title, detail string) Finding {
	return finding(id, file, line, title, detail)
}

// allowedCapabilities are the capabilities the baseline standard allows a
// container to add.
var allowedCapabilities = []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
	"SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}

// podSpecPaths say where each workload keeps its pod spec.
var podSpecPaths = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
}

// get returns the value of key in a mapping node.
func get(node *yaml.Node, keys ...string) *yaml.Node {
	for _, key := range keys {
		if node == nil {
			return nil
		}
		if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
			node = node.Content[0]
		}
		if node.Kind != yaml.MappingNode {
			return nil
		}
		var found *yaml.Node
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Value == key {
				found = node.Content[index+1]
			}
		}
		node = found
	}
	return node
}

// keyLine is the line of key in a mapping node, or the node's own.
func keyLine(node *yaml.Node, key string) int {
	if node != nil && node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Value == key {
				return node.Content[index].Line
			}
		}
	}
	if node != nil {
		return node.Line
	}
	return 1
}

func text(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func isTrue(node *yaml.Node) bool  { return text(node) == "true" }
func isFalse(node *yaml.Node) bool { return text(node) == "false" }

func items(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

func stringList(node *yaml.Node) []string {
	var result []string
	for _, item := range items(node) {
		result = append(result, text(item))
	}
	return result
}

// checkManifests checks every Kubernetes object in a YAML file. Documents
// that aren't Kubernetes objects, such as CI workflows, are left alone.
func checkManifests(file string, data []byte) ([]Finding, []string) {
	if bytes.Contains(data, []byte("{{")) {
		if !bytes.Contains(data, []byte("kind:")) {
			return nil, nil // a template of something else, such as .goreleaser.yaml
		}
		return nil, []string{file + ": a template (it has {{ }}); render it first, as in helm template CHART | deaconguard config scan -"}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var findings []Finding
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return findings, []string{fmt.Sprintf("%s: not valid YAML: %v", file, err)}
		}
		object := &document
		if document.Kind == yaml.DocumentNode && len(document.Content) > 0 {
			object = document.Content[0]
		}
		findings = append(findings, checkObject(file, object)...)
	}
	return findings, nil
}

func checkObject(file string, object *yaml.Node) []Finding {
	if object == nil || object.Kind != yaml.MappingNode {
		return nil
	}
	kind, apiVersion := text(get(object, "kind")), text(get(object, "apiVersion"))
	if kind == "" || apiVersion == "" {
		return nil
	}
	if kind == "List" || strings.HasSuffix(kind, "List") {
		var findings []Finding
		for _, item := range items(get(object, "items")) {
			findings = append(findings, checkObject(file, item)...)
		}
		return findings
	}
	name := text(get(object, "metadata", "name"))
	if name == "" {
		name = text(get(object, "metadata", "generateName")) + "*"
	}
	label := kind + " " + name
	if namespace := text(get(object, "metadata", "namespace")); namespace != "" {
		label = kind + " " + namespace + "/" + name
	}
	findings := objectFindings(file, label, kind, object)
	// The deaconguard.io/ignore annotation accepts findings for the object,
	// on the object or its pod template: "DG-K8S-002, DG-K8S-003".
	ignored := map[string]bool{}
	for _, annotations := range []*yaml.Node{get(object, "metadata", "annotations"), get(object, "spec", "template", "metadata", "annotations")} {
		for _, id := range strings.FieldsFunc(text(get(annotations, "deaconguard.io/ignore")), func(r rune) bool { return r == ',' || r == ' ' }) {
			ignored[strings.ToUpper(id)] = true
		}
	}
	var kept []Finding
	for _, f := range findings {
		if !ignored[f.Rule] {
			kept = append(kept, f)
		}
	}
	return kept
}

func objectFindings(file, label, kind string, object *yaml.Node) []Finding {
	if path, ok := podSpecPaths[kind]; ok {
		if spec := get(object, path...); spec != nil {
			return checkPodSpec(file, label, spec)
		}
		return nil
	}
	switch kind {
	case "ClusterRoleBinding", "RoleBinding":
		if role := get(object, "roleRef"); text(get(role, "name")) == "cluster-admin" && text(get(role, "kind")) == "ClusterRole" {
			return []Finding{finding("DG-K8S-020", file, keyLine(role, "name"), label+": grants cluster-admin",
				"cluster-admin can do anything in the cluster. Bind a role with only the verbs and resources its subjects use; keep cluster-admin for break-glass accounts.")}
		}
	case "ClusterRole", "Role":
		return checkRole(file, label, object)
	}
	return nil
}

func checkRole(file, label string, object *yaml.Node) []Finding {
	var findings []Finding
	for _, rule := range items(get(object, "rules")) {
		verbs, resources, groups := stringList(get(rule, "verbs")), stringList(get(rule, "resources")), stringList(get(rule, "apiGroups"))
		line := rule.Line
		if slices.Contains(verbs, "*") && slices.Contains(resources, "*") {
			findings = append(findings, finding("DG-K8S-021", file, line, label+": grants every action on every resource",
				"A wildcard rule grants everything, including resources added later. List the verbs and resources the role needs."))
			continue
		}
		core := len(groups) == 0 || slices.Contains(groups, "") || slices.Contains(groups, "*")
		if core && (slices.Contains(resources, "secrets") || slices.Contains(resources, "*")) &&
			slices.ContainsFunc(verbs, func(v string) bool { return v == "get" || v == "list" || v == "watch" || v == "*" }) {
			findings = append(findings, finding("DG-K8S-022", file, line, label+": can read secrets",
				"Whoever has this role can read every secret in its namespace (or the cluster, for a ClusterRole), including service account tokens. Name the secrets it needs with resourceNames, or give it none."))
		}
		escalates := slices.ContainsFunc(verbs, func(v string) bool { return v == "escalate" || v == "bind" || v == "impersonate" })
		execs := slices.Contains(resources, "pods/exec") && slices.ContainsFunc(verbs, func(v string) bool { return v == "create" || v == "*" })
		if escalates || execs {
			findings = append(findings, finding("DG-K8S-023", file, line, label+": can escalate its privileges",
				"escalate, bind and impersonate let a subject act with more rights than the role gives, and create on pods/exec runs commands in any pod. Remove them unless an operator needs them."))
		}
	}
	return findings
}

func checkPodSpec(file, label string, spec *yaml.Node) []Finding {
	var findings []Finding
	add := func(id string, line int, title, detail string) {
		findings = append(findings, finding(id, file, line, label+": "+title, detail))
	}
	for _, key := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if isTrue(get(spec, key)) {
			add("DG-K8S-002", keyLine(spec, key), key+": true",
				"The pod sees and can reach the node's own "+map[string]string{"hostNetwork": "network interfaces and services on localhost", "hostPID": "processes", "hostIPC": "shared memory"}[key]+". Remove it unless the pod is a node agent that needs it.")
		}
	}
	for _, volume := range items(get(spec, "volumes")) {
		if path := get(volume, "hostPath"); path != nil {
			add("DG-K8S-003", keyLine(volume, "hostPath"), fmt.Sprintf("volume %s mounts %s from the node", text(get(volume, "name")), text(get(path, "path"))),
				"A hostPath volume gives the pod the node's files; a writable one, or one with the container runtime's socket, lets it take over the node. Use a persistentVolumeClaim, configMap, secret or emptyDir.")
		}
	}
	podContext := get(spec, "securityContext")
	podNonRoot, podUser := isTrue(get(podContext, "runAsNonRoot")), text(get(podContext, "runAsUser"))
	podSeccomp := text(get(podContext, "seccompProfile", "type"))
	if podSeccomp == "Unconfined" {
		add("DG-K8S-006", keyLine(get(podContext, "seccompProfile"), "type"), "seccompProfile: Unconfined",
			"Without seccomp, containers can make every system call, including ones used to break out. Use RuntimeDefault.")
	}
	if isTrue(get(spec, "automountServiceAccountToken")) || get(spec, "automountServiceAccountToken") == nil {
		if text(get(spec, "serviceAccountName")) == "" {
			add("DG-K8S-016", spec.Line, "gets the default service account's token",
				"Pods get an API token unless told otherwise. Set automountServiceAccountToken: false unless the pod calls the Kubernetes API, and give the ones that do their own service account.")
		}
	}
	for _, list := range []string{"initContainers", "containers", "ephemeralContainers"} {
		for _, container := range items(get(spec, list)) {
			findings = append(findings, checkContainer(file, label, container, podNonRoot, podUser, podSeccomp)...)
		}
	}
	return findings
}

func checkContainer(file, label string, container *yaml.Node, podNonRoot bool, podUser, podSeccomp string) []Finding {
	var findings []Finding
	name := "container " + text(get(container, "name"))
	add := func(id string, line int, title, detail string) {
		findings = append(findings, finding(id, file, line, label+": "+name+" "+title, detail))
	}
	security := get(container, "securityContext")
	// line is where key is set, or the securityContext, or the container.
	line := func(key string) int {
		switch {
		case get(security, key) != nil:
			return keyLine(security, key)
		case security != nil:
			return security.Line
		}
		return container.Line
	}
	if isTrue(get(security, "privileged")) {
		add("DG-K8S-001", line("privileged"), "is privileged",
			"A privileged container has every capability and the node's devices: it is root on the node. Remove privileged and add only the capabilities it needs.")
	}
	added := stringList(get(security, "capabilities", "add"))
	var dangerous []string
	for _, capability := range added {
		if !slices.Contains(allowedCapabilities, strings.TrimPrefix(strings.ToUpper(capability), "CAP_")) {
			dangerous = append(dangerous, capability)
		}
	}
	if len(dangerous) > 0 {
		add("DG-K8S-004", line("capabilities"), "adds "+strings.Join(dangerous, ", "),
			"Capabilities such as SYS_ADMIN, NET_ADMIN and SYS_PTRACE let a container escape or watch others. Drop them, and add only NET_BIND_SERVICE or the others the baseline standard allows.")
	}
	for _, port := range items(get(container, "ports")) {
		if hostPort := text(get(port, "hostPort")); hostPort != "" && hostPort != "0" {
			add("DG-K8S-005", keyLine(port, "hostPort"), "uses port "+hostPort+" on the node",
				"A hostPort ties the pod to a node's port and bypasses Services and network policies. Expose it with a Service instead.")
		}
	}
	if text(get(security, "procMount")) == "Unmasked" || text(get(security, "seccompProfile", "type")) == "Unconfined" ||
		text(get(security, "appArmorProfile", "type")) == "Unconfined" {
		add("DG-K8S-006", container.Line, "turns off seccomp, AppArmor or /proc masking",
			"These keep a container from reaching the node's kernel interfaces. Leave them at their defaults (RuntimeDefault, Default).")
	}
	if !isFalse(get(security, "allowPrivilegeEscalation")) && !isTrue(get(security, "privileged")) {
		add("DG-K8S-007", line("allowPrivilegeEscalation"), "may gain privileges (allowPrivilegeEscalation isn't false)",
			"setuid programs and file capabilities can make the container's process more privileged. Set allowPrivilegeEscalation: false.")
	}
	user := text(get(security, "runAsUser"))
	if user == "" {
		user = podUser
	}
	nonRoot := isTrue(get(security, "runAsNonRoot")) || (podNonRoot && !isFalse(get(security, "runAsNonRoot")))
	switch {
	case user == "0":
		add("DG-K8S-009", line("runAsUser"), "runs as root (runAsUser: 0)",
			"Run as an unprivileged user ID, such as runAsUser: 10001, with runAsNonRoot: true.")
	case !nonRoot && user == "":
		add("DG-K8S-008", line("runAsNonRoot"), "may run as root (runAsNonRoot isn't true)",
			"Unless the image sets a user, the container runs as root. Set runAsNonRoot: true, so Kubernetes refuses to start it as root, and a runAsUser.")
	}
	if !slices.ContainsFunc(stringList(get(security, "capabilities", "drop")), func(c string) bool { return strings.EqualFold(c, "ALL") }) && !isTrue(get(security, "privileged")) {
		add("DG-K8S-010", line("capabilities"), "doesn't drop all capabilities",
			"Containers start with capabilities they rarely need. Drop them all (capabilities: drop: [ALL]) and add back only NET_BIND_SERVICE if it binds ports below 1024.")
	}
	seccomp := text(get(security, "seccompProfile", "type"))
	if seccomp == "" {
		seccomp = podSeccomp
	}
	if seccomp == "" {
		add("DG-K8S-011", container.Line, "has no seccomp profile",
			"Set seccompProfile: {type: RuntimeDefault} on the pod or container, so the runtime blocks system calls containers don't need.")
	}
	if !isTrue(get(security, "readOnlyRootFilesystem")) {
		add("DG-K8S-012", line("readOnlyRootFilesystem"), "has a writable root file system",
			"Set readOnlyRootFilesystem: true, and mount an emptyDir where the application writes, so an attacker can't change its files.")
	}
	if get(container, "resources", "limits", "memory") == nil {
		add("DG-K8S-013", keyLine(container, "resources"), "has no memory limit",
			"Without a limit one container can use all of a node's memory. Set resources.limits.memory, and requests.")
	}
	if image := text(get(container, "image")); image != "" && !strings.Contains(image, "@") && !strings.Contains(image, "$") {
		last := image[strings.LastIndex(image, "/")+1:]
		if !strings.Contains(last, ":") || strings.HasSuffix(image, ":latest") {
			add("DG-K8S-014", keyLine(container, "image"), "uses "+image+", not pinned to a version",
				"Name a version tag, or better a digest (image@sha256:…), so every node runs the same, checked image.")
		}
	}
	for _, variable := range items(get(container, "env")) {
		key := text(get(variable, "name"))
		if looksSecret(key, text(get(variable, "value"))) {
			add("DG-K8S-015", keyLine(variable, "value"), "has the secret "+key+" written in the manifest",
				"Anyone who can read the manifest, or the object in the cluster, can read it. Put it in a Secret and use valueFrom.secretKeyRef.")
		}
	}
	return findings
}
