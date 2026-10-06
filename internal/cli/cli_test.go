package cli

import (
	"bytes"
	"encoding/json"
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
