package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"deaconguard/internal/store"
)

func TestHostAddTakesNoAddress(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	var output, diagnostics bytes.Buffer
	if code := Run([]string{"host", "add", "new.example"}, nil, &output, &diagnostics); code == 0 ||
		!strings.Contains(diagnostics.String(), "takes no address") || !strings.Contains(diagnostics.String(), "agent") {
		t.Fatalf("host add with an address: code %d, %s", code, diagnostics.String())
	}
	if hosts, err := store.ListHosts(); err != nil || len(hosts) != 0 {
		t.Fatalf("hosts = %+v, %v", hosts, err)
	}
}

func TestHostAddRegistersThisMachine(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	var output, diagnostics bytes.Buffer
	code := Run([]string{"host", "add"}, nil, &output, &diagnostics)
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if code == 0 {
			t.Fatalf("host add on %s: code %d, %s", runtime.GOOS, code, diagnostics.String())
		}
		return
	}
	hosts, err := store.ListHosts()
	if code != 0 || err != nil || len(hosts) != 1 || hosts[0].Transport != store.TransportLocal {
		t.Fatalf("host add: code %d, %s, hosts %+v, %v", code, diagnostics.String(), hosts, err)
	}
	want := store.KindMachine
	if runtime.GOOS == "darwin" {
		want = store.KindMac
	}
	if hosts[0].Kind != want {
		t.Errorf("host add on %s: kind %q, want %q", runtime.GOOS, hosts[0].Kind, want)
	}
}

func TestReportCommandPrintsStoredJSON(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	report, err := store.SaveReport(map[string]any{
		"host_id": "host-id", "address": "debian.example", "os": "Debian 13 (trixie)",
		"finding_count": 1, "findings": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	code := Run([]string{"report", report["report_id"].(string), "--json"}, nil, &output, &diagnostics)
	if code != 0 {
		t.Fatalf("report command failed: %s", diagnostics.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["os"] != "Debian 13 (trixie)" || decoded["finding_count"] != float64(1) {
		t.Fatalf("unexpected report JSON: %+v", decoded)
	}
}

func TestVersionCommand(t *testing.T) {
	for _, argument := range []string{"version", "--version", "-v"} {
		var output bytes.Buffer
		if code := Run([]string{argument}, nil, &output, &output); code != 0 || !strings.HasPrefix(output.String(), "deaconguard ") {
			t.Fatalf("%s: code %d, output %q", argument, code, output.String())
		}
	}
}

func TestImageScanOfAFolder(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	dir := t.TempDir()
	run := func(arguments ...string) (string, int) {
		var out, diagnostics strings.Builder
		code := Run(append([]string{"image", "scan"}, arguments...), strings.NewReader(""), &out, &diagnostics)
		return out.String() + diagnostics.String(), code
	}
	if out, code := run("dir:"+dir, "--format", "sarif"); code != 0 || !strings.Contains(out, `"version": "2.1.0"`) {
		t.Fatalf("sarif: %d %s", code, out)
	}
	if out, code := run(dir, "--format", "junit", "--fail-on", "high"); code != 0 || !strings.Contains(out, "Nothing found") {
		t.Fatalf("junit: %d %s", code, out)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if out, code := run("dir:"+dir, "--format", "json", "--output", report); code != 0 || !strings.Contains(out, "Wrote the json report to") {
		t.Fatalf("--output: %d %s", code, out)
	}
	if data, err := os.ReadFile(report); err != nil || !strings.Contains(string(data), `"vulnerabilities": []`) {
		t.Fatalf("report file: %s %v", data, err)
	}
	if out, code := run("dir:"+dir, "--format", "cyclonedx"); code == 0 || !strings.Contains(out, "no package list") {
		t.Fatalf("an SBOM of nothing: %d %s", code, out)
	}
	if out, code := run("dir:"+dir, "--format", "xml"); code == 0 || !strings.Contains(out, "--format is one of") {
		t.Fatalf("an unknown format: %d %s", code, out)
	}
}

func TestConfigScan(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.22\nUSER 1000\nHEALTHCHECK CMD true\n"), 0o644)
	run := func(stdin string, arguments ...string) (string, int) {
		var out, diagnostics strings.Builder
		code := Run(append([]string{"config"}, arguments...), strings.NewReader(stdin), &out, &diagnostics)
		return out.String() + diagnostics.String(), code
	}
	if out, code := run("", "scan", dir, "--fail-on", "low"); code != 0 || !strings.Contains(out, "Checked 1 file: 0 findings") {
		t.Fatalf("a clean Dockerfile: %d %s", code, out)
	}
	pod := "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n    - name: c\n      image: x:1\n      securityContext: {privileged: true}\n"
	if out, code := run(pod, "scan", "-", "--fail-on", "critical"); code != 4 || !strings.Contains(out, "-:8 Pod p: container c is privileged [DG-K8S-001]") {
		t.Fatalf("a privileged pod: %d %s", code, out)
	}
	if out, code := run(pod, "scan", "-", "--format", "sarif"); code != 0 || !strings.Contains(out, `"startLine": 8`) || !strings.Contains(out, `"uri": "-"`) {
		t.Fatalf("sarif: %d %s", code, out)
	}
	if out, code := run("", "rules"); code != 0 || !strings.Contains(out, "DG-K8S-001") || !strings.Contains(out, "Pod Security Standards") {
		t.Fatalf("rules: %d %s", code, out)
	}
	if out, code := run(pod, "scan", "-", "--fail-on", "critical", "--skip", "dg-k8s-001"); code != 0 || strings.Contains(out, "DG-K8S-001") {
		t.Fatalf("--skip: %d %s", code, out)
	}
	if _, code := run("", "scan"); code == 0 {
		t.Fatal("no path")
	}
}

func TestEnvironmentCredentialsStayWithTheirRegistry(t *testing.T) {
	t.Setenv("DEACONGUARD_REGISTRY_USERNAME", "gitlab-ci-token")
	t.Setenv("DEACONGUARD_REGISTRY_PASSWORD", "job-token")
	t.Setenv("DEACONGUARD_REGISTRY", "")
	credentials, err := environmentCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if login, ok := credentials("registry-1.docker.io"); !ok || login.Password != "job-token" {
		t.Fatal("without DEACONGUARD_REGISTRY, the login goes to the image's registry")
	}
	t.Setenv("DEACONGUARD_REGISTRY", "https://registry.gitlab.com/")
	credentials, _ = environmentCredentials()
	if _, ok := credentials("registry-1.docker.io"); ok {
		t.Fatal("the GitLab login was given to Docker Hub")
	}
	if login, ok := credentials("registry.gitlab.com"); !ok || login.Username != "gitlab-ci-token" {
		t.Fatal("the login didn't reach its own registry")
	}
	t.Setenv("DEACONGUARD_REGISTRY", "not a host")
	if _, err := environmentCredentials(); err == nil {
		t.Fatal("a bad DEACONGUARD_REGISTRY was accepted")
	}
}

func TestNetAndTLSCommands(t *testing.T) {
	run := func(arguments ...string) (string, int) {
		var out, diagnostics strings.Builder
		code := Run(arguments, strings.NewReader(""), &out, &diagnostics)
		return out.String() + diagnostics.String(), code
	}
	if out, code := run("net", "scan", "127.0.0.1", "--ports", "1", "--timeout", "500ms", "--format", "json"); code != 0 || !strings.Contains(out, `"addresses": 1`) {
		t.Fatalf("net scan: %d %s", code, out)
	}
	if out, code := run("net", "scan", "10.0.0.0/8"); code == 0 || !strings.Contains(out, "smaller range") {
		t.Fatalf("a /8: %d %s", code, out)
	}
	if out, code := run("net", "scan", "127.0.0.1", "--ports", "0"); code == 0 || !strings.Contains(out, "not a port") {
		t.Fatalf("port 0: %d %s", code, out)
	}
	if out, code := run("tls", "check", "127.0.0.1:1"); code != 0 || !strings.Contains(out, "Checked TLS on 0 of 1") || !strings.Contains(out, "no TLS handshake") {
		t.Fatalf("tls on a closed port: %d %s", code, out)
	}
	if _, code := run("tls"); code == 0 {
		t.Fatal("tls without check")
	}
}

func TestHostListSaysWhichAgentsToUpgrade(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	previous := store.ServerVersion
	t.Cleanup(func() { store.ServerVersion = previous })
	store.ServerVersion = "1.23.0"
	_, secret, err := store.CreateEnrollmentToken("https://server:8444", "admin", store.TokenOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.21.0", "1.23.0"} {
		if _, _, err := store.EnrollAgent(secret, store.AgentEnrollment{Hostname: "web-" + version, Username: "root", Version: version, OS: "Ubuntu 24.04 LTS"}); err != nil {
			t.Fatal(err)
		}
	}
	var output, diagnostics bytes.Buffer
	if code := Run([]string{"host", "list"}, nil, &output, &diagnostics); code != 0 {
		t.Fatalf("host list: code %d, %s", code, diagnostics.String())
	}
	for _, want := range []string{"web-1.21.0  (agent 1.21.0, upgrade to 1.23.0)", "web-1.23.0  (agent 1.23.0)\n",
		"1 agent is older than this server, DeaconGuard 1.23.0", "DEACONGUARD_VERSION=1.23.0 sudo -E sh -"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q in:\n%s", want, output.String())
		}
	}
}
