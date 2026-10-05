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

func TestInstallCommand(t *testing.T) {
	saved := Version
	defer func() { Version = saved }()
	for version, want := range map[string]string{
		"0.2.0":                  "curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/download/v0.2.0/install.sh | sudo sh -s -- --agent --version 0.2.0",
		"0.2.0-rc.1":             "curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/download/v0.2.0-rc.1/install.sh | sudo sh -s -- --agent --version 0.2.0-rc.1",
		"dev":                    "curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh | sudo sh -s -- --agent",
		"0.1.1-3-gabc1234-dirty": "curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh | sudo sh -s -- --agent",
	} {
		Version = version
		if got := InstallCommand("agent"); got != want {
			t.Errorf("InstallCommand for %s = %q, want %q", version, got, want)
		}
	}
}
