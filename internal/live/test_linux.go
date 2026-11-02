//go:build linux

package live

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func newMachine(hostRoot string) Machine { return newProcMachine(hostRoot) }

// runTestProgram starts a harmless program from a temporary folder, which
// the temporary program rule catches and marks as a test: a copy of
// true, or of the agent itself asked for its version, removed at once.
func runTestProgram(hostRoot string) error {
	source, args := "", []string{}
	for _, candidate := range []string{"/usr/bin/true", "/bin/true"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			source = candidate
			break
		}
	}
	if source == "" {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		source, args = executable, []string{"version"}
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	root := hostRoot
	if root == "" {
		root = "/"
	}
	var lastErr error
	for _, folder := range []string{"tmp", "var/tmp", "dev/shm"} {
		target := filepath.Join(root, folder, "deaconguard-test-"+hex.EncodeToString(suffix))
		if err := copyExecutable(source, target); err != nil {
			lastErr = err
			continue
		}
		command := exec.Command(target, args...)
		command.Stdout, command.Stderr = io.Discard, io.Discard
		err := command.Start()
		if err == nil {
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				command.Process.Kill()
			}
		}
		os.Remove(target)
		if err == nil {
			return nil
		}
		lastErr = err
		if !errors.Is(err, os.ErrPermission) {
			break
		}
	}
	return fmt.Errorf("couldn't start the test program from a temporary folder (they may not allow running programs): %w", lastErr)
}

func copyExecutable(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(target)
		return err
	}
	return out.Close()
}
