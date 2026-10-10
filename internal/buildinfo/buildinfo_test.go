package buildinfo

import (
	"strings"
	"testing"
)

func TestStringShortensCommitButKeepsDirtyMarker(t *testing.T) {
	previousVersion, previousCommit, previousDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = previousVersion, previousCommit, previousDate })
	Version, Commit, Date = "1.2.3", "0123456789abcdef0123-dirty", "2026-09-29T10:00:00Z"
	got := String()
	if !strings.HasPrefix(got, "deaconguard 1.2.3 (commit 0123456789ab-dirty, built 2026-09-29T10:00:00Z") {
		t.Fatalf("String() = %q", got)
	}
	if UserAgent() != "DeaconGuard/1.2.3 (+https://github.com/Cloudopsshell/deaconguard)" {
		t.Fatalf("UserAgent() = %q", UserAgent())
	}
}

func TestAgentInstallCommand(t *testing.T) {
	saved := Version
	defer func() { Version = saved }()
	const get = "curl -fsSL https://get.deaconguard.io | "
	for _, test := range []struct{ version, token, want string }{
		{"0.4.1", "deaconguard1.abc.def", get + "DEACONGUARD_VERSION=0.4.1 DEACONGUARD_TOKEN=deaconguard1.abc.def sh -"},
		{"0.5.0-rc.1", "", get + "DEACONGUARD_VERSION=0.5.0-rc.1 sh -s -- --agent"},
		{"dev", "deaconguard1.abc", get + "DEACONGUARD_TOKEN=deaconguard1.abc sh -"},
		{"0.1.1-3-gabc1234-dirty", "", get + "sh -s -- --agent"},
	} {
		Version = test.version
		if got := AgentInstallCommand(test.token); got != test.want {
			t.Errorf("AgentInstallCommand for %s = %q, want %q", test.version, got, test.want)
		}
	}
}
