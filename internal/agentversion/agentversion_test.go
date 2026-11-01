package agentversion

import (
	"slices"
	"testing"
)

func TestUpgradeFor(t *testing.T) {
	for _, test := range []struct {
		agent, server string
		nudged        bool
	}{
		{"1.21.0", "1.23.0", true},
		{"1.23.0", "1.23.0", false},
		{"1.24.0", "1.23.0", false},
		{"1.22.0-rc.1", "1.22.0", true},
		{"1.22.0", "1.22.0-rc.1", false},
		{"1.22.0-rc.2", "1.22.0-rc.10", true},
		{"1.22.9", "1.22.10", true},
		{"dev", "1.23.0", false},
		{"", "1.23.0", false},
		{"1.21.0", "dev", false},
		{"1.21.0", "1.23.0-dev", false},
		{"1.21.0", "1.23.0-rc.1", true},
		{"1.21.0junk", "1.23.0", false},
	} {
		if got := UpgradeFor(test.agent, test.server, false); (got != nil) != test.nudged {
			t.Errorf("UpgradeFor(%q, %q) = %+v, nudged %v", test.agent, test.server, got, test.nudged)
		}
	}
	upgrade := UpgradeFor("1.4.2", "1.23.0", false)
	if !slices.Equal(upgrade.Checks, []string{"changes", "kubernetes"}) {
		t.Errorf("checks = %v", upgrade.Checks)
	}
	if upgrade.Command != "curl -fsSL https://get.deaconguard.io | DEACONGUARD_VERSION=1.23.0 sudo -E sh -" {
		t.Errorf("command = %q", upgrade.Command)
	}
	if UpgradeFor("1.21.0", "1.23.0", true).Command != "" {
		t.Error("an agent in Kubernetes got the install script")
	}
	if checks := UpgradeFor("1.22.0", "1.23.0", false).Checks; len(checks) != 0 {
		t.Errorf("1.22.0 lacks %v", checks)
	}
}
