package lifecycle

import (
	"testing"
	"time"

	"deaconguard/internal/platform"
)

func TestAlpine(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	if got := Of(platform.Platform{Family: platform.Alpine, VersionID: "3.22.1", Major: 3, Minor: 22}, now); got.State != Supported || got.Until != "2027-05-01" {
		t.Errorf("3.22 = %+v", got)
	}
	if got := Of(platform.Platform{Family: platform.Alpine, VersionID: "3.20.6", Major: 3, Minor: 20}, now); got.State != Ended {
		t.Errorf("3.20 = %+v, want ended (2026-04-01)", got)
	}
	if got := Of(platform.Platform{Family: platform.Alpine, VersionID: "3.30.0", Major: 3, Minor: 30}, now); got.State != Unknown {
		t.Errorf("3.30 = %+v, want unknown", got)
	}
}
