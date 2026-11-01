// Package agentversion knows which agent versions run which checks, and
// what upgrading an agent older than its server brings. It imports nothing
// of DeaconGuard's, so the store can use it.
package agentversion

import (
	"fmt"
	"sort"
	"strings"
)

// CheckSince is the agent version (major, minor) that added each check that
// older agents don't have.
var CheckSince = map[string][2]int{"yara": {0, 5}, "hardening": {0, 12}, "libraries": {1, 1}, "containers": {1, 2}, "kubernetes": {1, 5}, "changes": {1, 22}, "paths": {1, 26}}

// LiveSince is the agent version that added live detection (1.27.0).
var LiveSince = [2]int{1, 27}

// SupportsLive reports whether an agent of version runs live detection.
// Builds without a release version, such as "dev", are assumed to.
func SupportsLive(version string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d.", &major, &minor); err != nil {
		return version != ""
	}
	return major > LiveSince[0] || (major == LiveSince[0] && minor >= LiveSince[1])
}

// SupportsCheck reports whether an agent of version runs check. Builds
// without a release version, such as "dev", are assumed to.
func SupportsCheck(version, check string) bool {
	since, limited := CheckSince[check]
	if !limited {
		return true
	}
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d.", &major, &minor); err != nil {
		return version != ""
	}
	return major > since[0] || (major == since[0] && minor >= since[1])
}

// Upgrade is what upgrading an agent older than its server brings, so the
// dashboard and the CLI can say so (1.23.0 and later).
type Upgrade struct {
	// To is the server's version, the one to upgrade the agent to.
	To string `json:"to"`
	// Checks are the checks the agent can't run until it's upgraded.
	Checks []string `json:"checks,omitempty"`
	// Live is set when the agent can't run live detection until it's
	// upgraded (1.27.0 and later).
	Live bool `json:"live,omitempty"`
	// Command upgrades an agent installed with the install script, on a
	// Linux machine or a Mac; empty for agents in Kubernetes, which are
	// upgraded with their Helm release or Kustomize overlay.
	Command string `json:"command,omitempty"`
}

// UpgradeFor says what upgrading an agent of version brings, given the
// server's version, or nil when the agent is as new as the server. A build
// without a release version on either side, such as "dev", is never nudged,
// nor are agents of a development server ("1.23.0-dev"), which has no
// published build to upgrade them to.
func UpgradeFor(version, server string, kubernetes bool) *Upgrade {
	agentRelease, ok := parseRelease(version)
	if !ok {
		return nil
	}
	serverRelease, ok := parseRelease(server)
	if !ok || strings.Contains(serverRelease.prerelease, "dev") || compareReleases(agentRelease, serverRelease) >= 0 {
		return nil
	}
	upgrade := &Upgrade{To: server}
	for check := range CheckSince {
		if !SupportsCheck(version, check) && SupportsCheck(server, check) {
			upgrade.Checks = append(upgrade.Checks, check)
		}
	}
	sort.Strings(upgrade.Checks)
	upgrade.Live = !SupportsLive(version) && SupportsLive(server)
	if !kubernetes {
		upgrade.Command = InstallCommand(server)
	}
	return upgrade
}

// InstallCommand upgrades an agent installed with the install script to
// version, keeping its enrollment.
func InstallCommand(version string) string {
	return "curl -fsSL https://get.deaconguard.io | DEACONGUARD_VERSION=" + version + " sudo -E sh -"
}

// release is a version's major, minor and patch numbers, and its
// pre-release, such as "rc.1", which comes before the release itself.
type release struct {
	numbers    [3]int
	prerelease string
}

func parseRelease(version string) (release, bool) {
	core, prerelease, _ := strings.Cut(version, "-")
	var parsed release
	var rest string
	if count, _ := fmt.Sscanf(core, "%d.%d.%d%s", &parsed.numbers[0], &parsed.numbers[1], &parsed.numbers[2], &rest); count < 3 || rest != "" {
		return release{}, false
	}
	parsed.prerelease = prerelease
	return parsed, true
}

func compareReleases(left, right release) int {
	for index := range left.numbers {
		if left.numbers[index] != right.numbers[index] {
			if left.numbers[index] < right.numbers[index] {
				return -1
			}
			return 1
		}
	}
	switch {
	case left.prerelease == right.prerelease:
		return 0
	case left.prerelease == "":
		return 1
	case right.prerelease == "":
		return -1
	}
	return comparePrerelease(left.prerelease, right.prerelease)
}

// comparePrerelease orders pre-releases such as "rc.2" and "rc.10" by their
// dot-separated parts, numbers as numbers.
func comparePrerelease(left, right string) int {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < len(leftParts) && index < len(rightParts); index++ {
		var leftNumber, rightNumber int
		_, leftErr := fmt.Sscanf(leftParts[index], "%d", &leftNumber)
		_, rightErr := fmt.Sscanf(rightParts[index], "%d", &rightNumber)
		switch {
		case leftErr == nil && rightErr == nil && leftNumber != rightNumber:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		case leftErr != nil || rightErr != nil:
			if comparison := strings.Compare(leftParts[index], rightParts[index]); comparison != 0 {
				return comparison
			}
		}
	}
	switch {
	case len(leftParts) < len(rightParts):
		return -1
	case len(leftParts) > len(rightParts):
		return 1
	}
	return 0
}
