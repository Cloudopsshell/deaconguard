package runstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 10, 15, 21, 26, 0, time.UTC)

// fakeBoot makes the machine's boot ID id for the rest of the test.
func fakeBoot(t *testing.T, id string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := bootIDPath
	bootIDPath = path
	t.Cleanup(func() { bootIDPath = previous })
}

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// started records a run in a new directory and returns the directory.
func started(t *testing.T) (string, *Run) {
	t.Helper()
	directory := t.TempDir()
	run, previous, err := Start(directory, "0.5.1", now.Add(-time.Hour))
	if err != nil || previous != nil {
		t.Fatalf("first Start() = %v, %v", previous, err)
	}
	t.Cleanup(func() { run.Stopped(now) })
	return directory, run
}

func restart(t *testing.T, directory string) *Stop {
	t.Helper()
	run, previous, err := Start(directory, "0.5.1", now)
	if err != nil || previous == nil {
		t.Fatalf("Start() = %v, %v", previous, err)
	}
	t.Cleanup(func() { run.Stopped(now) })
	return previous
}

func TestCleanStop(t *testing.T) {
	fakeBoot(t, "boot-1")
	directory, run := started(t)
	run.Stopped(now.Add(-time.Minute))
	RecordSystemdResult(directory, env(map[string]string{"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}), now)
	stop := restart(t, directory)
	if stop.Kind != KindStopped || stop.Unexpected() || stop.StoppedAt == nil {
		t.Fatalf("stop = %+v", stop)
	}
}

func TestReboot(t *testing.T) {
	fakeBoot(t, "boot-1")
	directory, run := started(t)
	run.Stopped(now.Add(-time.Minute))
	fakeBoot(t, "boot-2")
	if stop := restart(t, directory); stop.Kind != KindReboot || !stop.Unexpected() || strings.Contains(stop.Message, "power") {
		t.Fatalf("clean reboot = %+v", stop)
	}

	// No clean stop before the new boot: power loss or a forced stop.
	fakeBoot(t, "boot-3")
	if stop := restart(t, directory); stop.Kind != KindReboot || !strings.Contains(stop.Message, "power loss") {
		t.Fatalf("hard reboot = %+v", stop)
	}
}

func TestOutOfMemory(t *testing.T) {
	fakeBoot(t, "boot-1")
	directory, _ := started(t)
	RecordSystemdResult(directory, env(map[string]string{"SERVICE_RESULT": "oom-kill", "EXIT_CODE": "killed", "EXIT_STATUS": "KILL"}), now)
	if stop := restart(t, directory); stop.Kind != KindOutOfMemory || !strings.Contains(stop.Message, "out of memory") {
		t.Fatalf("stop = %+v", stop)
	}
}

func TestKilledBySignal(t *testing.T) {
	fakeBoot(t, "boot-1")
	directory, _ := started(t)
	RecordSystemdResult(directory, env(map[string]string{"SERVICE_RESULT": "signal", "EXIT_CODE": "killed", "EXIT_STATUS": "KILL"}), now)
	if stop := restart(t, directory); stop.Kind != KindKilled || !strings.Contains(stop.Message, "signal KILL") {
		t.Fatalf("stop = %+v", stop)
	}
}

func TestCrashReportIsKept(t *testing.T) {
	fakeBoot(t, "boot-1")
	directory, _ := started(t)
	// What Go writes to the crash output when the process panics.
	report := "panic: runtime error: index out of range [3] with length 3\n\ngoroutine 42 [running]:\ndeaconguard/internal/advisory.evaluate(...)\n"
	if err := os.WriteFile(filepath.Join(directory, crashFile), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	RecordSystemdResult(directory, env(map[string]string{"SERVICE_RESULT": "exit-code", "EXIT_CODE": "exited", "EXIT_STATUS": "2"}), now)
	stop := restart(t, directory)
	if stop.Kind != KindCrashed || !strings.Contains(stop.Message, "index out of range") || !strings.Contains(stop.Detail, "goroutine 42") {
		t.Fatalf("stop = %+v", stop)
	}
	// The new run starts with an empty crash file.
	if contents, _ := os.ReadFile(filepath.Join(directory, crashFile)); len(contents) != 0 {
		t.Fatalf("crash file = %q", contents)
	}
}

func TestUnrecordedStop(t *testing.T) {
	fakeBoot(t, "boot-1")
	directory, _ := started(t)
	if stop := restart(t, directory); stop.Kind != KindUnknown || !strings.Contains(stop.Message, "journalctl -k") {
		t.Fatalf("stop = %+v", stop)
	}
}

func TestDamagedRecordNeverBlocksStart(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, stateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	run, previous, err := Start(directory, "0.5.1", now)
	if err != nil || previous != nil {
		t.Fatalf("Start() = %v, %v", previous, err)
	}
	run.Stopped(now)
}

func TestRecordStopNeedsSystemd(t *testing.T) {
	directory, _ := started(t)
	if err := RecordSystemdResult(directory, env(nil), now); err == nil {
		t.Fatal("recorded a stop without SERVICE_RESULT")
	}
}
