package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"opsarmor/internal/store"
)

func TestHostAddListRemoveCommands(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	var output, diagnostics bytes.Buffer
	code := Run([]string{"host", "add", "ubuntu.example", "--username", "scanner", "--port", "2222"}, nil, &output, &diagnostics)
	if code != 0 {
		t.Fatalf("host add failed: %s", diagnostics.String())
	}
	if !strings.Contains(output.String(), "Added ubuntu.example") {
		t.Fatalf("unexpected add output: %s", output.String())
	}
	hosts, err := store.ListHosts()
	if err != nil || len(hosts) != 1 || hosts[0].Port != 2222 {
		t.Fatalf("stored hosts = %+v, %v", hosts, err)
	}
	output.Reset()
	if code := Run([]string{"host", "list"}, nil, &output, &diagnostics); code != 0 {
		t.Fatalf("host list failed: %s", diagnostics.String())
	}
	if !strings.Contains(output.String(), hosts[0].ID) {
		t.Fatalf("host list omitted the registered host: %s", output.String())
	}
	output.Reset()
	if code := Run([]string{"host", "remove", hosts[0].ID}, nil, &output, &diagnostics); code != 0 {
		t.Fatalf("host remove failed: %s", diagnostics.String())
	}
	if remaining, err := store.ListHosts(); err != nil || len(remaining) != 0 {
		t.Fatalf("remaining hosts = %+v, %v", remaining, err)
	}
}

func TestReportCommandPrintsStoredJSON(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
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
		if code := Run([]string{argument}, nil, &output, &output); code != 0 || !strings.HasPrefix(output.String(), "opsarmor ") {
			t.Fatalf("%s: code %d, output %q", argument, code, output.String())
		}
	}
}
