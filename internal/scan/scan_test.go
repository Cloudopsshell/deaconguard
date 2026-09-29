package scan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opsarmor/internal/checks"
	"opsarmor/internal/store"
	"opsarmor/internal/target"
)

// fakeTarget answers the fixed commands a scan sends, like an Ubuntu host would.
type fakeTarget struct {
	answers  map[string]string
	observer target.CommandObserver
	ran      []string
}

func (f *fakeTarget) Run(command string, _ []byte, _ int, _ time.Duration) ([]byte, error) {
	f.ran = append(f.ran, command)
	if f.observer != nil {
		f.observer.CommandStarted(command)
		defer f.observer.CommandFinished(command, 0, 0, nil)
	}
	for prefix, answer := range f.answers {
		if strings.HasPrefix(command, prefix) {
			return []byte(answer), nil
		}
	}
	return nil, nil
}
func (f *fakeTarget) Observe(observer target.CommandObserver) { f.observer = observer }
func (f *fakeTarget) Close() error                            { return nil }

func TestRunTargetRunsChecksOnAnyTarget(t *testing.T) {
	osRelease, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "rootfs", "etc", "os-release"))
	if err != nil {
		t.Fatal(err)
	}
	machine := &fakeTarget{answers: map[string]string{
		"cat /etc/os-release":   string(osRelease),
		"for f in /etc/ssh":     "==> /etc/ssh/sshd_config <==\nPermitRootLogin yes\nPasswordAuthentication no\n",
		"ss -H -tuln":           "tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:*\n",
		"cat /etc/apt/apt.conf": `APT::Periodic::Unattended-Upgrade "1";` + "\n",
	}}
	host := store.Host{ID: "local-id", Address: "this-machine", Username: "scanner", Transport: store.TransportLocal}
	var events []Event
	report, err := RunTarget(machine, host, []string{checks.Config}, Options{Progress: func(event Event) { events = append(events, event) }})
	if err != nil {
		t.Fatal(err)
	}
	if report["os"] != "Ubuntu 22.04 LTS" || report["address"] != "this-machine" {
		t.Fatalf("report = %+v", report)
	}
	result := report["check_results"].(map[string]checks.Result)[checks.Config]
	rules := map[string]bool{}
	for _, finding := range result.Findings {
		rules[finding.Rule] = true
	}
	if !rules["config.ssh-root-login"] || !rules["config.exposed-service"] || rules["config.ssh-password-auth"] {
		t.Fatalf("config findings = %+v", result.Findings)
	}
	for _, command := range machine.ran {
		if strings.Contains(command, "sudo") {
			t.Fatalf("sudo was used without consent: %q", command)
		}
	}
	commands := 0
	for _, event := range events {
		if event.Kind == "command" {
			commands++
		}
	}
	if commands != len(machine.ran) {
		t.Fatalf("progress showed %d commands, target ran %d", commands, len(machine.ran))
	}
}

func TestRunTargetFailsWhenTheOSIsUnreadable(t *testing.T) {
	machine := &failingTarget{}
	host := store.Host{Address: "broken", Transport: store.TransportLocal}
	if _, err := RunTarget(machine, host, []string{checks.Config}, Options{}); err == nil {
		t.Fatal("a scan that cannot read /etc/os-release must fail, not report clean")
	}
}

type failingTarget struct{}

func (failingTarget) Run(string, []byte, int, time.Duration) ([]byte, error) {
	return nil, errors.New("permission denied")
}
func (failingTarget) Observe(target.CommandObserver) {}
func (failingTarget) Close() error                   { return nil }
