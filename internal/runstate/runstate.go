// Package runstate records how each run of the server ends, so the next run
// can say why the previous one stopped: a clean stop, a reboot of the machine,
// the kernel stopping it for lack of memory, or a crash. It keeps a small
// state file and Go's crash output in the data directory; systemd adds how
// the process ended through `deaconguard record-stop` (ExecStopPost).
package runstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const (
	stateFile = "server-run.json"
	crashFile = "server-crash.log"
	// maxCrash bounds how much of a crash report is kept: the panic message
	// and the first stack frames say what failed.
	maxCrash = 8 << 10
)

// bootIDPath changes on every boot of a Linux machine.
var bootIDPath = "/proc/sys/kernel/random/boot_id"

// Kinds of Stop, from the most to the least certain.
const (
	KindStopped     = "stopped"       // stopped cleanly: systemctl stop or restart, or an upgrade
	KindReboot      = "reboot"        // the machine restarted
	KindOutOfMemory = "out_of_memory" // the kernel stopped it for lack of memory
	KindCrashed     = "crashed"       // DeaconGuard crashed; Detail holds the report
	KindKilled      = "killed"        // ended by a signal or an error exit
	KindUnknown     = "unknown"       // ended without a clean stop, cause not recorded
)

// Stop says how the previous run of the server ended.
type Stop struct {
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	StartedAt time.Time `json:"started_at"`
	// DetectedAt is when the next run found out, which is as close as
	// DeaconGuard gets to when it stopped if the stop was not recorded.
	DetectedAt time.Time `json:"detected_at"`
	// StoppedAt is set when the stop itself was recorded.
	StoppedAt *time.Time `json:"stopped_at,omitempty"`
	Version   string     `json:"version,omitempty"`
	// Detail is the start of a crash report.
	Detail string `json:"detail,omitempty"`
}

// Unexpected reports whether the stop was not asked for, so an administrator
// should know about it.
func (s Stop) Unexpected() bool { return s.Kind != KindStopped }

// state is what a run records about itself.
type state struct {
	BootID    string     `json:"boot_id"`
	PID       int        `json:"pid"`
	Version   string     `json:"version"`
	StartedAt time.Time  `json:"started_at"`
	StoppedAt *time.Time `json:"stopped_at,omitempty"`
	// Systemd is how systemd saw the process end, from ExecStopPost.
	Systemd *systemdResult `json:"systemd,omitempty"`
}

type systemdResult struct {
	Result     string    `json:"result"`
	ExitCode   string    `json:"exit_code"`
	ExitStatus string    `json:"exit_status"`
	At         time.Time `json:"at"`
}

// Run is the record of the current run.
type Run struct {
	directory string
	state     state
	crash     *os.File
}

// Start records a new run in directory and returns how the previous one
// ended; previous is nil on the first run. Go writes a crash of this run to
// the crash file from now on.
func Start(directory, version string, now time.Time) (*Run, *Stop, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, nil, err
	}
	bootID := readBootID()
	// A missing or unreadable record means there is nothing to explain; it
	// must never stop the server from starting.
	var previous *Stop
	if old, err := readState(directory); err == nil {
		crash, _ := os.ReadFile(filepath.Join(directory, crashFile))
		stop := explain(old, bootID, crash, now)
		previous = &stop
	}
	run := &Run{directory: directory, state: state{BootID: bootID, PID: os.Getpid(), Version: version, StartedAt: now.UTC()}}
	if err := run.save(); err != nil {
		return nil, nil, err
	}
	crash, err := os.OpenFile(filepath.Join(directory, crashFile), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := debug.SetCrashOutput(crash, debug.CrashOptions{}); err != nil {
		crash.Close()
		return nil, nil, err
	}
	run.crash = crash
	return run, previous, nil
}

// Stopped records a clean stop.
func (r *Run) Stopped(now time.Time) error {
	at := now.UTC()
	r.state.StoppedAt = &at
	debug.SetCrashOutput(nil, debug.CrashOptions{})
	r.crash.Close()
	return r.save()
}

func (r *Run) save() error { return writeState(r.directory, r.state) }

// RecordSystemdResult stores how systemd saw the run end, from the variables
// it passes to ExecStopPost: SERVICE_RESULT, EXIT_CODE and EXIT_STATUS.
func RecordSystemdResult(directory string, getenv func(string) string, now time.Time) error {
	current, err := readState(directory)
	if err != nil {
		return err
	}
	result := getenv("SERVICE_RESULT")
	if result == "" {
		return errors.New("SERVICE_RESULT is not set; record-stop runs from the service's ExecStopPost")
	}
	current.Systemd = &systemdResult{Result: result, ExitCode: getenv("EXIT_CODE"), ExitStatus: getenv("EXIT_STATUS"), At: now.UTC()}
	return writeState(directory, current)
}

// explain turns what the previous run recorded into a Stop.
func explain(old state, bootID string, crash []byte, now time.Time) Stop {
	stop := Stop{StartedAt: old.StartedAt, DetectedAt: now.UTC(), Version: old.Version, StoppedAt: old.StoppedAt}
	rebooted := old.BootID != "" && bootID != "" && old.BootID != bootID
	report := crashReport(crash)
	clean := old.StoppedAt != nil
	if old.Systemd != nil {
		at := old.Systemd.At
		if stop.StoppedAt == nil {
			stop.StoppedAt = &at
		}
		switch old.Systemd.Result {
		case "success":
			clean = true
		case "oom-kill":
			stop.Kind = KindOutOfMemory
			stop.Message = "The machine ran out of memory and the kernel stopped the DeaconGuard server."
			return stop
		}
	}
	switch {
	case report != "":
		stop.Kind, stop.Detail = KindCrashed, report
		stop.Message = "The DeaconGuard server crashed: " + firstLine(report)
	case clean && rebooted:
		stop.Kind = KindReboot
		stop.Message = "The machine restarted."
	case clean:
		stop.Kind = KindStopped
		stop.Message = "The DeaconGuard server was stopped, for example by an upgrade or systemctl restart."
	case rebooted:
		stop.Kind = KindReboot
		stop.Message = "The machine restarted without stopping DeaconGuard first, for example after a power loss or a forced stop of the instance."
	case old.Systemd != nil:
		stop.Kind = KindKilled
		stop.Message = killedMessage(*old.Systemd)
	default:
		stop.Kind = KindUnknown
		stop.Message = "The DeaconGuard server stopped unexpectedly, and the cause was not recorded. If the machine is short of memory, the kernel may have stopped it: check sudo journalctl -k | grep -i oom."
	}
	return stop
}

func killedMessage(result systemdResult) string {
	switch result.ExitCode {
	case "killed", "dumped":
		message := "The DeaconGuard server was stopped by signal " + result.ExitStatus
		if result.ExitStatus == "KILL" {
			message += ", which the kernel sends when the machine runs out of memory, and which kill -9 sends"
		}
		return message + "."
	case "exited":
		return "The DeaconGuard server exited with status " + result.ExitStatus + ". See: sudo journalctl -u deaconguard-server"
	}
	return fmt.Sprintf("The DeaconGuard server stopped (systemd result %q). See: sudo journalctl -u deaconguard-server", result.Result)
}

// crashReport returns the start of Go's crash output, which begins with the
// panic or fatal error message.
func crashReport(crash []byte) string {
	crash = bytes.TrimSpace(crash)
	if len(crash) > maxCrash {
		crash = crash[:maxCrash]
	}
	return strings.ToValidUTF8(string(crash), "")
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	if len(line) > 200 {
		line = line[:200] + "…"
	}
	return line
}

func readBootID() string {
	contents, err := os.ReadFile(bootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}

func readState(directory string) (state, error) {
	var current state
	contents, err := os.ReadFile(filepath.Join(directory, stateFile))
	if err != nil {
		return current, err
	}
	if err := json.Unmarshal(contents, &current); err != nil {
		return current, fmt.Errorf("read %s: %w", stateFile, err)
	}
	return current, nil
}

// writeState replaces the state file in one step, so a crash mid-write never
// leaves half a file.
func writeState(directory string, current state) error {
	contents, err := json.Marshal(current)
	if err != nil {
		return err
	}
	temporary := filepath.Join(directory, stateFile+".tmp")
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(directory, stateFile))
}
