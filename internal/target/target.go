// Package target defines how OpsArmor runs commands on a machine it scans,
// independent of how it reaches that machine. Today that is the machine
// OpsArmor runs on (internal/local); the planned agent will use the same
// interface. Every command is a fixed, read-only string from OpsArmor's source.
package target

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"opsarmor/internal/platform"
)

const (
	MaxOSReleaseBytes = 16 * 1024
	MaxPackageBytes   = 32 << 20
	CommandTimeout    = 60 * time.Second
)

// Target is a machine being scanned.
type Target interface {
	// Run executes command, feeding stdin if it is not nil, and returns at
	// most limit bytes of output. When the command runs but exits non-zero,
	// the output is returned with an error that satisfies ExitStatus.
	Run(command string, stdin []byte, limit int, timeout time.Duration) ([]byte, error)
	// Observe reports every later command to observer, for live progress.
	Observe(observer CommandObserver)
	Close() error
}

// CommandObserver is told about every command a target runs. It never
// receives command input, which can hold a sudo password.
type CommandObserver interface {
	CommandStarted(command string)
	CommandFinished(command string, outputBytes int, elapsed time.Duration, err error)
}

// ExitStatus reports the exit status when err means a command ran and exited
// non-zero, as opposed to failing to run, timing out, or losing the connection.
func ExitStatus(err error) (int, bool) {
	var exit interface{ ExitStatus() int }
	if errors.As(err, &exit) {
		return exit.ExitStatus(), true
	}
	return 0, false
}

// Inventory is what the package vulnerability check evaluates.
type Inventory struct {
	OSRelease  string `json:"os_release"`
	DPKGStatus string `json:"dpkg_status,omitempty"`
	RPMQuery   string `json:"rpm_query,omitempty"`
	Kernel     string `json:"kernel"`
}

// OSRelease reads /etc/os-release.
func OSRelease(t Target) (string, error) {
	osRelease, err := t.Run("cat /etc/os-release", nil, MaxOSReleaseBytes, CommandTimeout)
	if err != nil {
		return "", fmt.Errorf("read /etc/os-release: %w", err)
	}
	return string(osRelease), nil
}

// CollectInventory reads the OS release, installed packages, and running kernel.
func CollectInventory(t Target) (Inventory, error) {
	osRelease, err := OSRelease(t)
	if err != nil {
		return Inventory{}, err
	}
	detected, err := platform.Detect(osRelease)
	if err != nil {
		return Inventory{}, err
	}
	inventory := Inventory{OSRelease: osRelease}
	if detected.Family == platform.Ubuntu || detected.Family == platform.Debian {
		packages, err := t.Run("head -c 33554433 /var/lib/dpkg/status", nil, MaxPackageBytes, CommandTimeout)
		if err != nil {
			return Inventory{}, fmt.Errorf("read /var/lib/dpkg/status: %w", err)
		}
		inventory.DPKGStatus = string(packages)
	} else {
		query := "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{SOURCERPM}\\t%{ARCH}\\n'"
		packages, err := t.Run(query, nil, MaxPackageBytes, CommandTimeout)
		if err != nil {
			return Inventory{}, fmt.Errorf("collect installed RPM inventory: %w", err)
		}
		inventory.RPMQuery = string(packages)
	}
	kernel, err := t.Run("uname -r", nil, 256, CommandTimeout)
	if err != nil {
		return Inventory{}, fmt.Errorf("read running kernel: %w", err)
	}
	inventory.Kernel = strings.TrimSpace(string(kernel))
	if inventory.Kernel == "" || len(inventory.Kernel) > 256 {
		return Inventory{}, fmt.Errorf("running kernel release is missing or invalid")
	}
	return inventory, nil
}
