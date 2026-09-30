package checks

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"opsarmor/internal/target"
)

const maxSudoAttempts = 3

// Commander runs one command on the scanned host.
type Commander interface {
	Run(command string, stdin []byte, limit int, timeout time.Duration) ([]byte, error)
}

type sudoMode int

const (
	sudoUnknown sudoMode = iota
	sudoUnavailable
	sudoPasswordless
	sudoWithPassword
	// runningAsRoot needs no sudo: commands already have full access.
	runningAsRoot
)

// Executor runs a check's commands, through sudo when the host allows it.
// A sudo password is asked for at most once per scan, held in memory only,
// and cleared by Close.
type Executor struct {
	commander   Commander
	allowSudo   bool
	askPassword func(retry error) ([]byte, error)
	mode        sudoMode
	password    []byte
	note        string
}

func NewExecutor(commander Commander, allowSudo bool, askPassword func(retry error) ([]byte, error)) *Executor {
	return &Executor{commander: commander, allowSudo: allowSudo, askPassword: askPassword}
}

// AsRoot tells the executor the scanning account is root, so privileged
// commands run directly.
func (e *Executor) AsRoot() { e.mode = runningAsRoot }

// Run executes command as the scanning account. Output is returned even when the
// command exits non-zero, because verification tools report findings that way.
func (e *Executor) Run(command string, limit int, timeout time.Duration) ([]byte, int, error) {
	return exitCode(e.commander.Run(command, nil, limit, timeout))
}

// RunPrivileged executes command through sudo when it is available, and as
// the scanning account otherwise. privileged reports which one happened.
func (e *Executor) RunPrivileged(command string, limit int, timeout time.Duration) (output []byte, code int, privileged bool, err error) {
	if !e.sudo() {
		output, code, err = e.Run(command, limit, timeout)
		return output, code, false, err
	}
	if e.mode == runningAsRoot {
		output, code, err = e.Run(command, limit, timeout)
		return output, code, true, err
	}
	wrapped, stdin := e.wrap(command)
	output, code, err = exitCode(e.commander.Run(wrapped, stdin, limit, timeout))
	return output, code, true, err
}

// Privileged reports whether sudo is usable, asking for a password if needed.
func (e *Executor) Privileged() bool { return e.sudo() }

// SudoNote explains why checks ran without sudo, if they did.
func (e *Executor) SudoNote() string { return e.note }

func (e *Executor) Close() {
	clear(e.password)
	e.password = nil
}

func (e *Executor) wrap(command string) (string, []byte) {
	if e.mode == sudoWithPassword {
		return "sudo -S -p '' -- sh -c " + shellQuote(command), append(append([]byte(nil), e.password...), '\n')
	}
	return "sudo -n -- sh -c " + shellQuote(command), nil
}

func (e *Executor) sudo() bool {
	if e.mode != sudoUnknown {
		return e.mode == sudoPasswordless || e.mode == sudoWithPassword || e.mode == runningAsRoot
	}
	e.mode = sudoUnavailable
	if !e.allowSudo {
		e.note = "OpsArmor's \"use sudo\" setting is off for this host, so only what the scanning account can read was checked. Turn it on for full coverage."
		return false
	}
	output, _, err := exitCode(e.commander.Run("sudo -n true", nil, 4096, 30*time.Second))
	if err == nil {
		e.mode = sudoPasswordless
		return true
	}
	message := strings.ToLower(err.Error() + " " + string(output))
	if !strings.Contains(message, "password is required") {
		e.note = "Sudo is allowed for this host but is not available to the scanning account (" + truncate(err.Error(), 160) + "); checks ran without it."
		return false
	}
	if e.askPassword == nil {
		e.note = "Sudo requires a password on this host and none could be asked for; checks ran without sudo."
		return false
	}
	var retry error
	for attempt := 0; attempt < maxSudoAttempts; attempt++ {
		password, err := e.askPassword(retry)
		if err != nil {
			e.note = "The sudo password was not provided; checks ran without sudo."
			return false
		}
		// -k ignores any cached credentials so the password itself is verified.
		_, _, err = exitCode(e.commander.Run("sudo -k -S -p '' -- true", append(append([]byte(nil), password...), '\n'), 4096, 30*time.Second))
		if err == nil {
			e.password = password
			e.mode = sudoWithPassword
			return true
		}
		clear(password)
		retry = errors.New("sudo rejected that password")
	}
	e.note = fmt.Sprintf("The sudo password was rejected %d times; checks ran without sudo.", maxSudoAttempts)
	return false
}

// exitCode separates a non-zero exit status from other failures.
func exitCode(output []byte, err error) ([]byte, int, error) {
	if status, ok := target.ExitStatus(err); ok {
		return output, status, err
	}
	if err != nil {
		return output, -1, err
	}
	return output, 0, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
