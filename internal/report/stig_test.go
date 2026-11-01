package report

import (
	"testing"

	"deaconguard/internal/checks"
)

func TestSTIGText(t *testing.T) {
	rules := checks.STIGRules("Red Hat Enterprise Linux 9.4", "KRN-07")
	if got := STIGIDs(rules); got != "DISA RHEL 9 STIG V-257813, V-257814" {
		t.Errorf("STIGIDs = %q", got)
	}
	if got := STIGText(rules); got != "DISA RHEL 9 STIG V-257813, V-257814. The STIG asks for both '* hard core 0' and systemd-coredump Storage=none; this control passes with either." {
		t.Errorf("STIGText = %q", got)
	}
	if got := STIGText(checks.STIGRules("Ubuntu 24.04 LTS", "KRN-01")); got != "DISA Canonical Ubuntu 24.04 LTS STIG V-270772" {
		t.Errorf("no note: %q", got)
	}
}
