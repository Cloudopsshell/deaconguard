package scan

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDisplayCommandUnwrapsSudo(t *testing.T) {
	cases := []struct {
		command, want string
		sudo          bool
	}{
		{"dpkg --verify", "dpkg --verify", false},
		{`sudo -n -- sh -c 'printf '\''%s\n'\'' x'`, `printf '%s\n' x`, true},
		{`sudo -S -p '' -- sh -c 'ufw status 2>/dev/null'`, "ufw status 2>/dev/null", true},
		{"sudo -k -S -p '' -- true", "sudo -v   # verifying the sudo password", true},
	}
	for _, tc := range cases {
		got, sudo := displayCommand(tc.command)
		if got != tc.want || sudo != tc.sudo {
			t.Errorf("displayCommand(%q) = %q, %v; want %q, %v", tc.command, got, sudo, tc.want, tc.sudo)
		}
	}
}

type exitError struct{ status int }

func (e exitError) Error() string   { return "exit" }
func (e exitError) ExitStatus() int { return e.status }

func TestCommandResultsNeverIncludeOutput(t *testing.T) {
	var events []Event
	progress := &reporter{emit: func(event Event) { events = append(events, event) }, phase: "integrity"}
	progress.CommandStarted("sudo -S -p '' -- sh -c 'dpkg --verify'")
	progress.CommandFinished("", 2048, 1500*time.Millisecond, exitError{1})
	progress.CommandFinished("", 0, time.Second, errors.New("command timed out after 1m0s"))
	if len(events) != 3 || events[0].Message != "dpkg --verify" || !events[0].Sudo || events[0].Phase != "integrity" {
		t.Fatalf("events = %+v", events)
	}
	if events[1].Kind != "result" || events[1].Message != "exit 1 · 2.0 KB in 1.5s" {
		t.Fatalf("exit result = %+v", events[1])
	}
	if events[2].Kind != "error" || !strings.Contains(events[2].Message, "timed out") {
		t.Fatalf("error result = %+v", events[2])
	}
}
