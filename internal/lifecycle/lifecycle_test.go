package lifecycle

import (
	"testing"
	"time"

	"deaconguard/internal/platform"
)

func TestOf(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		target platform.Platform
		state  string
		until  string
	}{
		{platform.Platform{Family: platform.Ubuntu, VersionID: "24.04", Major: 24}, Supported, "2029-04"},
		{platform.Platform{Family: platform.Ubuntu, VersionID: "20.04", Major: 20}, Extended, "2030-04"},
		{platform.Platform{Family: platform.Debian, VersionID: "12", Major: 12}, Extended, "2028-06-30"},
		{platform.Platform{Family: platform.Debian, VersionID: "13", Major: 13}, Unknown, ""},
		{platform.Platform{Family: platform.Rocky, VersionID: "9.6", Major: 9, Minor: 6}, Supported, "2032-05-31"},
		{platform.Platform{Family: platform.OpenSUSELeap, VersionID: "15.6", Major: 15, Minor: 6}, Ended, "2026-04-30"},
		{platform.Platform{Family: platform.SLES, VersionID: "15.6", Major: 15, Minor: 6}, Extended, "2028-12-31"},
		{platform.Platform{Family: platform.SLES, VersionID: "15.4", Major: 15, Minor: 4}, Unknown, ""},
	} {
		got := Of(test.target, now)
		if got.State != test.state || got.Until != test.until || got.Note == "" {
			t.Errorf("%s %s: %+v", test.target.Family, test.target.VersionID, got)
		}
	}
	// A month-only date lasts to the end of that month.
	leap16 := platform.Platform{Family: platform.OpenSUSELeap, VersionID: "16.0", Major: 16}
	if got := Of(leap16, time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)); got.State != Supported {
		t.Fatalf("last day: %+v", got)
	}
	if got := Of(leap16, time.Date(2027, 11, 1, 0, 0, 0, 0, time.UTC)); got.State != Ended {
		t.Fatalf("after: %+v", got)
	}
}

func TestFedora(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct{ json, state, until string }{
		{`{"name":"F44","state":"current","eol":"2027-06-02"}`, Supported, "2027-06-02"},
		{`{"name":"F42","state":"archived","eol":"2026-05-27"}`, Ended, "2026-05-27"},
		{`{"name":"F43","state":"current","eol":"2026-01-01"}`, Ended, "2026-01-01"},
		{`{"name":"F45","state":"pending","eol":null}`, Supported, ""},
		{`not json`, Unknown, ""},
	} {
		if got := Fedora([]byte(test.json), now); got.State != test.state || got.Until != test.until {
			t.Errorf("%s: %+v", test.json, got)
		}
	}
}
