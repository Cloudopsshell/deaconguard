package advisory

import (
	"testing"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
)

func fixOf(t *testing.T, family platform.Family, packages []inventory.Package, kernel string, finding Finding) string {
	t.Helper()
	findings := []Finding{finding}
	Classify(findings, family, packages, kernel)
	return findings[0].Fix
}

func TestClassifyUbuntu(t *testing.T) {
	packages := []inventory.Package{
		{Name: "openssl", Version: "3.0.13-0ubuntu3.4"},
		{Name: "linux-image-6.8.0-31-generic", Version: "6.8.0-31.31"},
		{Name: "linux-image-6.8.0-35-generic", Version: "6.8.0-35.35"},
		{Name: "linux-modules-6.8.0-31-generic", Version: "6.8.0-31.31"},
	}
	const kernel = "6.8.0-31-generic"
	for name, test := range map[string]struct {
		finding Finding
		want    string
	}{
		"update available":   {Finding{Package: "openssl", FixedVersion: "3.0.13-0ubuntu3.5"}, FixAvailable},
		"no fix yet":         {Finding{Package: "openssl"}, FixNone},
		"Ubuntu Pro":         {Finding{Package: "libxmltok1t64", FixedVersion: "1.2-4.1ubuntu2.24.04.1+esm3"}, FixUbuntuPro},
		"reboot":             {Finding{Package: "running kernel", FixedVersion: "0:6.8.0-35"}, FixReboot},
		"kernel not fixed":   {Finding{Package: "running kernel", FixedVersion: "0:6.8.0-36"}, FixAvailable},
		"kernel, no fix yet": {Finding{Package: "running kernel"}, FixNone},
		"running modules":    {Finding{Package: "linux-modules-6.8.0-31-generic", FixedVersion: "6.8.0-36.36"}, FixAvailable},
	} {
		if got := fixOf(t, platform.Ubuntu, packages, kernel, test.finding); got != test.want {
			t.Errorf("%s: %s, want %s", name, got, test.want)
		}
	}
	// A fixed kernel of another flavour does not help the running one.
	aws := append([]inventory.Package{}, packages...)
	if got := fixOf(t, platform.Ubuntu, aws, "6.8.0-31-aws", Finding{Package: "running kernel", FixedVersion: "0:6.8.0-35"}); got != FixAvailable {
		t.Errorf("other flavour: %s", got)
	}
}

func TestClassifyDebian(t *testing.T) {
	packages := []inventory.Package{
		{Name: "linux-image-6.1.0-25-amd64", Version: "6.1.106-3", Source: "linux"},
		{Name: "linux-image-6.1.0-26-amd64", Version: "6.1.112-1", Source: "linux"},
	}
	fixed := "6.1.112-1"
	if got := fixOf(t, platform.Debian, packages, "6.1.0-26-amd64", Finding{Package: "linux-image-6.1.0-25-amd64", FixedVersion: fixed}); got != FixOldKernel {
		t.Errorf("old kernel: %s", got)
	}
	if got := fixOf(t, platform.Debian, packages, "6.1.0-25-amd64", Finding{Package: "linux-image-6.1.0-25-amd64", FixedVersion: fixed}); got != FixReboot {
		t.Errorf("reboot: %s", got)
	}
	if got := fixOf(t, platform.Debian, packages, "6.1.0-25-amd64", Finding{Package: "linux-image-6.1.0-25-amd64"}); got != FixNone {
		t.Errorf("open in the tracker: %s", got)
	}
	if got := fixOf(t, platform.Debian, packages, "6.1.0-26-amd64", Finding{Package: "curl", FixedVersion: "7.88.1-10+deb12u8"}); got != FixAvailable {
		t.Errorf("update: %s", got)
	}
}

func TestClassifyRPM(t *testing.T) {
	packages := []inventory.Package{
		{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4", Arch: "x86_64"},
		{Name: "kernel-core", Version: "5.14.0-427.20.1.el9_4", Arch: "x86_64"},
		{Name: "openssl", Version: "1:3.0.7-27.el9", Arch: "x86_64"},
	}
	fixed := "5.14.0-427.18.1.el9_4"
	for _, family := range []platform.Family{platform.RHEL, platform.AmazonLinux} {
		old := fixOf(t, family, packages, "5.14.0-427.20.1.el9_4.x86_64", Finding{Package: "kernel-core", InstalledVersion: "5.14.0-427.13.1.el9_4", FixedVersion: fixed})
		reboot := fixOf(t, family, packages, "5.14.0-427.13.1.el9_4.x86_64", Finding{Package: "kernel-core", InstalledVersion: "5.14.0-427.13.1.el9_4", FixedVersion: fixed})
		update := fixOf(t, family, packages, "5.14.0-427.20.1.el9_4.x86_64", Finding{Package: "openssl", InstalledVersion: "1:3.0.7-27.el9", FixedVersion: "1:3.0.7-28.el9_4"})
		if old != FixOldKernel || reboot != FixReboot || update != FixAvailable {
			t.Errorf("%s: old kernel %s, reboot %s, update %s", family, old, reboot, update)
		}
	}
}

func TestUbuntuSeverityIsUbuntusPriority(t *testing.T) {
	metadata := func(priority, cvss string) *ovalNode {
		cve := &ovalNode{Name: "cve", Attrs: []ovalAttr{{"priority", priority}, {"cvss_severity", cvss}}}
		return &ovalNode{Name: "metadata", Children: []*ovalNode{{Name: "advisory", Children: []*ovalNode{cve}}}}
	}
	for _, test := range []struct{ priority, cvss, severity, cvssSeverity string }{
		{"low", "critical", "LOW", "CRITICAL"},
		{"medium", "high", "MEDIUM", "HIGH"},
		{"negligible", "", "LOW", ""},
		{"untriaged", "high", "HIGH", "HIGH"},
		{"", "", "UNKNOWN", ""},
	} {
		severity, cvss := ubuntuSeverity(metadata(test.priority, test.cvss))
		if severity != test.severity || cvss != test.cvssSeverity {
			t.Errorf("priority %q, CVSS %q: %s / %s", test.priority, test.cvss, severity, cvss)
		}
	}
}
