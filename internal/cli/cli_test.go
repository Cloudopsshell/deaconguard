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

func TestHostCommandsWithLegacySSHHost(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("DEACONGUARD_HOME", directory)
	// A profile file from an earlier release is imported as a legacy SSH host.
	legacy := `[{"id":"0123456789abcdef0123456789abcdef","address":"old.example","username":"ubuntu","port":22,"key_path":null}]`
	if err := os.WriteFile(filepath.Join(directory, "hosts.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if code := Run([]string{"host", "add", "new.example", "--username", "ubuntu"}, nil, &output, &diagnostics); code == 0 ||
		!strings.Contains(diagnostics.String(), "SSH scanning was removed") {
		t.Fatalf("adding an SSH host: code %d, %s", code, diagnostics.String())
	}
	output.Reset()
	if code := Run([]string{"host", "list"}, nil, &output, &diagnostics); code != 0 ||
		!strings.Contains(output.String(), "old.example") || !strings.Contains(output.String(), "scanning removed") {
		t.Fatalf("host list: %s", output.String())
	}
	diagnostics.Reset()
	if code := Run([]string{"scan", "0123456789abcdef0123456789abcdef", "--checks", "config"}, nil, &output, &diagnostics); code == 0 ||
		!strings.Contains(diagnostics.String(), "SSH scanning was removed") {
		t.Fatalf("scanning a legacy SSH host: code %d, %s", code, diagnostics.String())
	}
	output.Reset()
	if code := Run([]string{"host", "remove", "0123456789abcdef0123456789abcdef"}, nil, &output, &diagnostics); code != 0 {
		t.Fatalf("host remove failed: %s", diagnostics.String())
	}
	if remaining, err := store.ListHosts(); err != nil || len(remaining) != 0 {
		t.Fatalf("remaining hosts = %+v, %v", remaining, err)
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
