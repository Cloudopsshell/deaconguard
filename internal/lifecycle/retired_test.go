package lifecycle

import (
	"strings"
	"testing"
	"time"
)

func TestRetiredRelease(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		osRelease, name, version, upgrade, until string
	}{
		{"ID=debian\nVERSION_ID=\"10\"\nVERSION_CODENAME=buster\n", "Debian 10 (buster)", "10 (buster)", "13 (trixie)", "2024-06-30"},
		{"ID=debian\nVERSION_ID=\"11\"\n", "Debian 11 (bullseye)", "11 (bullseye)", "13 (trixie)", "2026-08-31"},
		{"ID=alpine\nVERSION_ID=3.15.4\n", "Alpine Linux 3.15", "3.15", "3.24", "2023-11-01"},
		{"ID=alpine\nVERSION_ID=3.9.2\n", "Alpine Linux 3.9", "3.9", "3.24", ""},
		{"ID=\"centos\"\nNAME=\"CentOS Linux\"\nVERSION_ID=\"7\"\n", "CentOS Linux 7", "7", "Rocky Linux or AlmaLinux 9", "2024-06-30"},
		{"ID=\"centos\"\nNAME=\"CentOS Stream\"\nVERSION_ID=\"8\"\n", "CentOS Stream 8", "8", "Rocky Linux or AlmaLinux 9", "2024-05-31"},
		{"ID=\"amzn\"\nVERSION_ID=\"2\"\n", "Amazon Linux 2", "2", "2023", "2026-06-30"},
		{"ID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"\n", "openSUSE Leap 15.5", "15.5", "16.0", "2024-12-31"},
	}
	for _, c := range cases {
		r, ok := RetiredRelease(c.osRelease, now)
		if !ok || r.Name != c.name || r.Version != c.version || r.Upgrade != c.upgrade || r.Lifecycle.State != Ended || r.Lifecycle.Until != c.until {
			t.Errorf("%q: %+v, %v", c.osRelease, r, ok)
		}
	}
	for _, supported := range []string{
		"ID=debian\nVERSION_ID=\"12\"\n", "ID=alpine\nVERSION_ID=3.18.4\n", "ID=ubuntu\nVERSION_ID=\"16.04\"\n",
		"ID=\"centos\"\nNAME=\"CentOS Stream\"\nVERSION_ID=\"9\"\n", "not an os-release",
	} {
		if r, ok := RetiredRelease(supported, now); ok {
			t.Errorf("%q isn't one DeaconGuard knows to have ended: %+v", supported, r)
		}
	}
	// Debian 11's LTS still ran in August 2026.
	if _, ok := RetiredRelease("ID=debian\nVERSION_ID=\"11\"\n", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("Debian 11 ended on 31 August 2026, not before")
	}
}

func TestRetiredExplain(t *testing.T) {
	r, _ := RetiredRelease("ID=debian\nVERSION_ID=\"10\"\n", time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC))
	want := "Debian 10 (buster) reached end of life on 30 June 2024 and gets no security fixes, so its packages can't be checked against advisories; upgrade to Debian 13 (trixie)."
	if got := r.Explain(); got != want {
		t.Errorf("Explain() = %q", got)
	}
	if !strings.Contains(r.Lifecycle.Note, "End of life since 30 June 2024") {
		t.Errorf("note = %q", r.Lifecycle.Note)
	}
}
