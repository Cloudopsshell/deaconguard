package iac

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func rules(findings []Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.Rule)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func lineOf(findings []Finding, rule string) int {
	for _, f := range findings {
		if f.Rule == rule {
			return f.Line
		}
	}
	return 0
}

const riskyDockerfile = `# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
RUN go build -o /app .

FROM ubuntu
ENV API_TOKEN=abc123 \
    MODE=prod
ARG DB_PASSWORD=hunter2
ARG GITHUB_TOKEN
RUN curl -fsSL https://example.com/install.sh | bash
RUN sudo apt-get update && chmod -R 777 /srv
ADD https://example.com/tool /usr/local/bin/tool
ADD config.yaml /etc/app/
COPY . /src
COPY --from=build /app /app
EXPOSE 8080 22
`

const hardenedDockerfile = `FROM golang:1.26@sha256:` + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + ` AS build
RUN go build -o /app .
FROM build AS test
RUN go test ./...
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION
ADD --checksum=sha256:abc https://example.com/tool.tar.gz /opt/
ADD rootfs.tar.gz /
COPY --from=build /app /app
USER 65532:65532
HEALTHCHECK CMD ["/app", "health"]
EXPOSE 8080
`

func TestDockerfileRules(t *testing.T) {
	findings := checkDockerfile("Dockerfile", riskyDockerfile, false)
	want := []string{"DG-DF-001", "DG-DF-002", "DG-DF-003", "DG-DF-004", "DG-DF-005", "DG-DF-006", "DG-DF-007", "DG-DF-008", "DG-DF-009", "DG-DF-010", "DG-DF-011"}
	if got := rules(findings); !slices.Equal(got, want) {
		t.Fatalf("rules = %v\nwant %v", got, want)
	}
	secrets := 0
	for _, f := range findings {
		if f.Rule == "DG-DF-003" {
			secrets++
			if strings.Contains(f.Title+f.Detail, "abc123") || strings.Contains(f.Title+f.Detail, "hunter2") {
				t.Errorf("a secret's value is shown: %+v", f)
			}
		}
	}
	if secrets != 2 {
		t.Errorf("%d secrets; want API_TOKEN and DB_PASSWORD, not GITHUB_TOKEN without a default", secrets)
	}
	if lineOf(findings, "DG-DF-004") != 10 || lineOf(findings, "DG-DF-003") != 6 || lineOf(findings, "DG-DF-002") != 5 {
		t.Errorf("lines: %+v", findings)
	}
	// golang:1.26 is pinned; the build stage isn't flagged for root, only the last stage.
	for _, f := range findings {
		if f.Rule == "DG-DF-002" && strings.Contains(f.Title, "golang") {
			t.Errorf("a pinned base flagged: %+v", f)
		}
	}

	if got := checkDockerfile("Dockerfile", hardenedDockerfile, true); len(got) != 0 {
		t.Errorf("hardened Dockerfile: %+v", got)
	}
	if got := rules(checkDockerfile("Dockerfile", "FROM alpine:3.22\nUSER root\nHEALTHCHECK NONE\n", true)); !slices.Equal(got, []string{"DG-DF-001", "DG-DF-011"}) {
		t.Errorf("USER root, HEALTHCHECK NONE: %v", got)
	}
	ignoring := "FROM alpine\n# deaconguard:ignore DG-DF-011, DG-DF-002\nUSER 1000\nENV TOKEN_FILE=/run/secrets/token PASSWORD_PATH=/etc/pw\n"
	if got := checkDockerfile("Dockerfile", ignoring, true); len(got) != 0 {
		t.Errorf("ignored rules and secret paths: %+v", got)
	}
	if got := checkDockerfile("notes", "just text\n", false); len(got) != 0 {
		t.Errorf("not a Dockerfile: %+v", got)
	}
}

const riskyManifests = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: docker
          hostPath:
            path: /var/run/docker.sock
      containers:
        - name: app
          image: acme/shop
          securityContext:
            privileged: true
            runAsUser: 0
            capabilities:
              add: ["SYS_ADMIN", "NET_BIND_SERVICE"]
          ports:
            - containerPort: 80
              hostPort: 80
          env:
            - name: DB_PASSWORD
              value: hunter2
            - name: API_TOKEN
              valueFrom:
                secretKeyRef: {name: api, key: token}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ops}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: ops, namespace: default}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: everything}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader}
rules:
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
`

const hardenedManifest = `apiVersion: batch/v1
kind: CronJob
metadata:
  name: report
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            seccompProfile: {type: RuntimeDefault}
          containers:
            - name: report
              image: ghcr.io/acme/report:2.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities: {drop: ["ALL"], add: ["NET_BIND_SERVICE"]}
              resources:
                limits: {memory: 256Mi}
`

func TestKubernetesRules(t *testing.T) {
	// A privileged container gets DG-K8S-001, not the capability and
	// privilege-escalation findings it implies.
	findings, notes := checkManifests("deploy.yaml", []byte(riskyManifests))
	if len(notes) != 0 {
		t.Fatalf("notes: %v", notes)
	}
	want := []string{"DG-K8S-001", "DG-K8S-002", "DG-K8S-003", "DG-K8S-004", "DG-K8S-005", "DG-K8S-009", "DG-K8S-011", "DG-K8S-012",
		"DG-K8S-013", "DG-K8S-014", "DG-K8S-015", "DG-K8S-016", "DG-K8S-020", "DG-K8S-021", "DG-K8S-022", "DG-K8S-023"}
	if got := rules(findings); !slices.Equal(got, want) {
		t.Fatalf("rules = %v\nwant %v", got, want)
	}
	for rule, line := range map[string]int{"DG-K8S-001": 17, "DG-K8S-002": 8, "DG-K8S-003": 11, "DG-K8S-005": 23, "DG-K8S-015": 26, "DG-K8S-020": 34} {
		if got := lineOf(findings, rule); got != line {
			t.Errorf("%s at line %d; want %d", rule, got, line)
		}
	}
	for _, f := range findings {
		if strings.Contains(f.Title+f.Detail, "hunter2") {
			t.Errorf("a secret's value is shown: %+v", f)
		}
		if f.Rule == "DG-K8S-004" && strings.Contains(f.Title, "NET_BIND_SERVICE") {
			t.Errorf("an allowed capability flagged: %s", f.Title)
		}
		if f.Rule == "DG-K8S-015" && strings.Contains(f.Title, "API_TOKEN") {
			t.Errorf("a secretKeyRef flagged: %s", f.Title)
		}
	}
	for _, f := range findings {
		if f.Rule == "DG-K8S-001" && f.Title != "Deployment shop: container app is privileged" {
			t.Errorf("title: %s", f.Title)
		}
	}

	if got, _ := checkManifests("cron.yaml", []byte(hardenedManifest)); len(got) != 0 {
		t.Errorf("hardened CronJob: %+v", got)
	}
	// Not Kubernetes: left alone.
	if got, notes := checkManifests("ci.yml", []byte("on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n")); len(got) != 0 || len(notes) != 0 {
		t.Errorf("a workflow: %+v %v", got, notes)
	}
	if _, notes := checkManifests("templates/deploy.yaml", []byte("kind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n")); len(notes) != 1 || !strings.Contains(notes[0], "helm template") {
		t.Errorf("a Helm template: %v", notes)
	}
	list := "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: Pod\n    metadata: {name: p}\n    spec:\n      containers: [{name: c, image: x:1, securityContext: {privileged: true}}]\n"
	if got, _ := checkManifests("list.yaml", []byte(list)); !slices.Contains(rules(got), "DG-K8S-001") {
		t.Errorf("a List: %v", rules(got))
	}
	annotated := "apiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: agent\n  annotations:\n    deaconguard.io/ignore: DG-K8S-002\nspec:\n  template:\n" +
		"    metadata:\n      annotations: {deaconguard.io/ignore: \"DG-K8S-003,DG-K8S-016\"}\n    spec:\n      hostPID: true\n" +
		"      volumes: [{name: host, hostPath: {path: /}}]\n      containers: []\n"
	if got, _ := checkManifests("agent.yaml", []byte(annotated)); len(got) != 0 {
		t.Errorf("annotated: %+v", got)
	}
	if _, notes := checkManifests(".goreleaser.yaml", []byte("builds:\n  - ldflags: -X main.version={{ .Version }}\n")); len(notes) != 0 {
		t.Errorf("a template that isn't Kubernetes: %v", notes)
	}
	if _, notes := checkManifests("bad.yaml", []byte("kind: [\n")); len(notes) != 1 {
		t.Errorf("bad YAML: %v", notes)
	}
}

func TestScanWalksFolders(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"Dockerfile":                 "FROM alpine\n",
		"services/api/Containerfile": "FROM alpine:3.22\nUSER 1000\nHEALTHCHECK CMD true\n",
		"deploy/app.yaml":            riskyManifests,
		".github/workflows/ci.yml":   "on: push\n",
		"node_modules/x/deploy.yaml": riskyManifests,
		"docs/README.md":             "# not checked\n",
		"deploy/kustomization.yml":   "resources: [app.yaml]\n",
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(body), 0o644)
	}
	result, err := Scan([]string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 4 {
		t.Errorf("files = %v; .github and node_modules are skipped", result.Files)
	}
	if result.Findings[0].Severity != "CRITICAL" {
		t.Errorf("not sorted by severity: %+v", result.Findings[0])
	}
	stdin, err := Scan([]string{"-"}, strings.NewReader(riskyManifests))
	if err != nil || len(stdin.Findings) == 0 || stdin.Findings[0].File != "-" {
		t.Errorf("stdin: %+v %v", stdin, err)
	}
	if len(Rules()) != len(dockerfileRules)+len(kubernetesRules) {
		t.Error("Rules")
	}
}
