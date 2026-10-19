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
	if runtime.GOOS != "linux" {
		if code == 0 || !strings.Contains(diagnostics.String(), "Linux only") {
			t.Fatalf("host add on %s: code %d, %s", runtime.GOOS, code, diagnostics.String())
		}
		return
	}
	hosts, err := store.ListHosts()
	if code != 0 || err != nil || len(hosts) != 1 || hosts[0].Transport != store.TransportLocal {
		t.Fatalf("host add: code %d, %s, hosts %+v, %v", code, diagnostics.String(), hosts, err)
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
	if out, code := run(dir, "--format", "junit", "--fail-on", "high"); code != 0 || !strings.Contains(out, "No vulnerabilities found") {
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
