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
	if UserAgent() != "DeaconGuard/1.2.3 (+https://github.com/Cloudopsshell/DeaconGuard)" {
		t.Fatalf("UserAgent() = %q", UserAgent())
	}
}
