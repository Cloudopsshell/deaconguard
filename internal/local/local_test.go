package local

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/target"
)

// run is exercised directly so the tests also pass on macOS, where New refuses.

func TestRunReturnsOutputAndUsesFixedLocale(t *testing.T) {
	output, err := run(`printf 'hello\n'; printf '%s' "$LC_ALL"`, nil, 1024, 5*time.Second)
	if err != nil || string(output) != "hello\nC" {
		t.Fatalf("output = %q, err = %v", output, err)
	}
}

func TestRunReportsExitStatusWithOutput(t *testing.T) {
	output, err := run(`echo partial; echo broken >&2; exit 3`, nil, 1024, 5*time.Second)
	status, ok := target.ExitStatus(err)
	if !ok || status != 3 || string(output) != "partial\n" || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("output = %q, err = %v, status = %d/%v", output, err, status, ok)
	}
}

func TestRunFeedsStdin(t *testing.T) {
	output, err := run(`cat`, []byte("secret\n"), 1024, 5*time.Second)
	if err != nil || string(output) != "secret\n" {
		t.Fatalf("output = %q, err = %v", output, err)
	}
}

func TestRunEnforcesOutputLimit(t *testing.T) {
	_, err := run(`yes | head -c 100000`, nil, 1000, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1000 bytes") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := target.ExitStatus(err); ok {
		t.Fatal("an oversized output must not look like an ordinary exit status")
	}
}

func TestRunTimeoutStopsTheWholePipeline(t *testing.T) {
	started := time.Now()
	_, err := run(`sleep 30 | cat`, nil, 1024, 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("timeout took %s; the pipeline kept running", elapsed)
	}
}

func TestNewOnlyOnLinux(t *testing.T) {
	_, err := New()
	if runtime.GOOS == "linux" && err != nil {
		t.Fatalf("New() on Linux: %v", err)
	}
	if runtime.GOOS != "linux" && !errors.Is(err, ErrUnsupportedOS) {
		t.Fatalf("New() on %s: %v", runtime.GOOS, err)
	}
}
