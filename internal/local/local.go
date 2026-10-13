// Package local scans the machine DeaconGuard itself runs on by running DeaconGuard's
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
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"deaconguard/internal/target"
)

const maxStderrBytes = 4 * 1024

// ErrUnsupportedOS is returned when DeaconGuard runs on a system it cannot scan.
var ErrUnsupportedOS = errors.New("local scanning is supported on Linux only")

// Target runs commands on this machine as the user running DeaconGuard.
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
	if _, err := os.Stat(HostPath("/bin/sh")); err != nil {
		if HostRoot() != "" {
			return nil, fmt.Errorf("no shell at %s: mount the host's root filesystem there", HostPath("/bin/sh"))
		}
		return nil, errors.New("this machine has no /bin/sh to run checks with; in a container, mount the host's root filesystem and set DEACONGUARD_HOST_ROOT")
	}
	return &Target{}, nil
}

// HostRoot is where the host's root filesystem is mounted when DeaconGuard
// runs in a container, from DEACONGUARD_HOST_ROOT, such as /host. Commands
// then run chrooted there, so they use the host's own tools and read its
// files, packages, and /proc. It is empty outside a container.
func HostRoot() string {
	root := os.Getenv("DEACONGUARD_HOST_ROOT")
	if root == "" || root == "/" {
		return ""
	}
	return filepath.Clean(root)
}

// HostPath is path on the host, under HostRoot. Symbolic links resolve
// inside the host's root, as they do for the commands chrooted there: hosts
// link /bin/sh to /bin/bash, or /etc/os-release to /usr/lib/os-release.
func HostPath(path string) string {
	root := HostRoot()
	if root == "" {
		return filepath.Join("/", path)
	}
	return filepath.Join(root, resolveIn(root, path))
}

// resolveIn follows symbolic links in path as if root were "/", and returns
// the result relative to root. A link that can't be read or loops ends the
// walk; the path then names something that doesn't exist.
func resolveIn(root, path string) string {
	pending := strings.Split(filepath.Clean("/"+path), "/")
	resolved := "/"
	for hops := 0; len(pending) > 0; {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			resolved = next
			continue
		}
		if hops++; hops > 40 {
			return filepath.Join(append([]string{next}, pending...)...)
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return resolved
}

// hostPATH is the search path for commands run in the host's root, since
// the container's own may not match the host's layout.
const hostPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Hostname and Username describe where and as whom local scans run. In a
// container, DEACONGUARD_HOSTNAME names the host, such as a Kubernetes node's
// name; otherwise the host's /etc/hostname does.
func Hostname() string {
	if name := strings.TrimSpace(os.Getenv("DEACONGUARD_HOSTNAME")); name != "" {
		return name
	}
	if HostRoot() != "" {
		if contents, err := os.ReadFile(HostPath("/etc/hostname")); err == nil {
			if name := strings.TrimSpace(string(contents)); name != "" {
				return name
			}
		}
	}
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
	if root := HostRoot(); root != "" {
		cmd.SysProcAttr.Chroot, cmd.Dir = root, "/"
		cmd.Env = append(cmd.Env, hostPATH)
	}
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
