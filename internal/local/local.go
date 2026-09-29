// Package local scans the machine OpsArmor itself runs on by running OpsArmor's
// fixed, read-only commands directly.
package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"

	"opsarmor/internal/target"
)

const maxStderrBytes = 4 * 1024

// ErrUnsupportedOS is returned when OpsArmor runs on a system it cannot scan.
var ErrUnsupportedOS = errors.New("local scanning is supported on Linux only")

// Target runs commands on this machine as the user running OpsArmor.
type Target struct {
	observer target.CommandObserver
}

var _ target.Target = (*Target)(nil)

// New returns a target for this machine. Only Linux is supported: the checks
// read Linux package databases, /proc, and /etc.
func New() (*Target, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w; this machine runs %s", ErrUnsupportedOS, runtime.GOOS)
	}
	return &Target{}, nil
}

// Hostname and Username describe where and as whom local scans run.
func Hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "localhost"
	}
	return name
}

func Username() string {
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return "unknown"
}

func (t *Target) Observe(observer target.CommandObserver) { t.observer = observer }

func (t *Target) Close() error { return nil }

func (t *Target) Run(command string, stdin []byte, limit int, timeout time.Duration) ([]byte, error) {
	if t.observer == nil {
		return run(command, stdin, limit, timeout)
	}
	t.observer.CommandStarted(command)
	started := time.Now()
	output, err := run(command, stdin, limit, timeout)
	t.observer.CommandFinished(command, len(output), time.Since(started), err)
	return output, err
}

// ExitError reports a command that ran and exited non-zero.
type ExitError struct {
	Status int
	Stderr string
}

func (e *ExitError) ExitStatus() int { return e.Status }

func (e *ExitError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("exit status %d: %s", e.Status, e.Stderr)
	}
	return fmt.Sprintf("exit status %d", e.Status)
}

var errOutputTooLarge = errors.New("command output exceeds the limit")

// limitedBuffer keeps at most limit bytes and then reports an error, which
// makes the command's writes fail so it stops early.
type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-b.buffer.Len() {
		b.exceeded = true
		return 0, errOutputTooLarge
	}
	return b.buffer.Write(value)
}

func run(command string, stdin []byte, limit int, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	// A fixed locale keeps tool output in the format the parsers expect.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	// Run in its own process group so a timeout stops pipelines, not just the shell.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	output := stdout.buffer.Bytes()
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return nil, fmt.Errorf("command timed out after %s", timeout)
	case stdout.exceeded:
		return nil, fmt.Errorf("command output exceeds %d bytes", limit)
	case err == nil:
		return output, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() >= 0 {
		return output, &ExitError{Status: exitError.ExitCode(), Stderr: strings.TrimSpace(stderr.buffer.String())}
	}
	return output, err
}
