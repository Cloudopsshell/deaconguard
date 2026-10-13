// Package lifecycle says whether a Linux release still gets security fixes
// from its vendor.
package lifecycle

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"deaconguard/internal/platform"
)

// States of a release.
const (
	// Supported: the vendor fixes security issues for everyone.
	Supported = "supported"
	// Extended: regular support ended; fixes continue only through paid or
	// community extended support, such as Ubuntu Pro or Debian LTS.
	Extended = "extended"
	// Ended: no security fixes at all.
	Ended = "ended"
	// Unknown: DeaconGuard has no date for this release.
	Unknown = "unknown"
)

// Lifecycle is where a release stands.
type Lifecycle struct {
	State string `json:"state"`
	// Until is when the current phase ends, as YYYY-MM or YYYY-MM-DD; for
	// Ended, when it ended.
	Until string `json:"until,omitempty"`
	// Note says what that means, such as "security fixes need Ubuntu Pro".
	Note string `json:"note"`
	// Source is the vendor's lifecycle page.
	Source string `json:"source,omitempty"`
}

// phase is a release's support: regular fixes until Regular, then extended
// fixes (named Extended) until ExtendedUntil.
type phase struct {
	Regular, ExtendedUntil, Extended, Source string
}

// releases are the vendors' published end dates, to the month where the
// vendor gives no day. Fedora is asked live; see Fedora.
var releases = map[platform.Family]map[string]phase{
	platform.Ubuntu: {
		"18.04": {"2023-05-31", "2028-04", "Ubuntu Pro (ESM)", "https://ubuntu.com/about/release-cycle"},
		"20.04": {"2025-05-29", "2030-04", "Ubuntu Pro (ESM)", "https://ubuntu.com/about/release-cycle"},
		"22.04": {"2027-04", "2032-04", "Ubuntu Pro (ESM)", "https://ubuntu.com/about/release-cycle"},
		"24.04": {"2029-04", "2034-04", "Ubuntu Pro (ESM)", "https://ubuntu.com/about/release-cycle"},
		"26.04": {"2031-04", "2036-04", "Ubuntu Pro (ESM)", "https://ubuntu.com/about/release-cycle"},
	},
	platform.Debian: {
		"12": {"2026-06-10", "2028-06-30", "Debian LTS", "https://wiki.debian.org/LTS"},
		"13": {"", "", "", "https://www.debian.org/security/faq"},
	},
	platform.AmazonLinux: {"2023": {"2029-06-30", "", "", "https://aws.amazon.com/linux/amazon-linux-2023/faqs/"}},
	platform.RHEL: {
		"8": {"2029-05-31", "", "", "https://access.redhat.com/support/policy/updates/errata"},
		"9": {"2032-05-31", "", "", "https://access.redhat.com/support/policy/updates/errata"},
	},
	platform.Rocky: {
		"8":  {"2029-05-31", "", "", "https://wiki.rockylinux.org/rocky/version/"},
		"9":  {"2032-05-31", "", "", "https://wiki.rockylinux.org/rocky/version/"},
		"10": {"2035-05-31", "", "", "https://wiki.rockylinux.org/rocky/version/"},
	},
	platform.Alma: {
		"8":  {"2029-03-01", "", "", "https://wiki.almalinux.org/release-notes/"},
		"9":  {"2032-05-31", "", "", "https://wiki.almalinux.org/release-notes/"},
		"10": {"2035-05-31", "", "", "https://wiki.almalinux.org/release-notes/"},
	},
	platform.Oracle: {
		"8":  {"2029-07", "", "", "https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf"},
		"9":  {"2032-06", "", "", "https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf"},
		"10": {"2035-06", "", "", "https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf"},
	},
	platform.OpenSUSELeap: {
		"15.6": {"2026-04-30", "", "", "https://en.opensuse.org/Lifetime"},
		"16.0": {"2027-10", "", "", "https://en.opensuse.org/Lifetime"},
	},
	platform.SLES: {
		"15.6": {"2025-12-31", "2028-12-31", "SUSE Long Term Service Pack Support (LTSS)", "https://www.suse.com/lifecycle/"},
		"15.7": {"2031-07-31", "2034-07-31", "SUSE LTSS", "https://www.suse.com/lifecycle/"},
	},
}

// Of says where target stands at now, from the published dates.
func Of(target platform.Platform, now time.Time) Lifecycle {
	release := target.VersionID
	switch target.Family {
	case platform.Debian, platform.RHEL, platform.Rocky, platform.Alma, platform.Oracle:
		release = fmt.Sprint(target.Major)
	}
	dates, known := releases[target.Family][release]
	if !known || dates.Regular == "" {
		return Lifecycle{State: Unknown, Note: "Check the distribution's lifecycle", Source: dates.Source}
	}
	today := now.UTC().Format("2006-01-02")
	if !passed(dates.Regular, today) {
		return Lifecycle{State: Supported, Until: dates.Regular, Note: "Security fixes until " + describe(dates.Regular), Source: dates.Source}
	}
	if dates.ExtendedUntil != "" && !passed(dates.ExtendedUntil, today) {
		return Lifecycle{State: Extended, Until: dates.ExtendedUntil, Source: dates.Source,
			Note: fmt.Sprintf("Regular support ended %s; security fixes need %s, until %s", describe(dates.Regular), dates.Extended, describe(dates.ExtendedUntil))}
	}
	ended := dates.Regular
	if dates.ExtendedUntil != "" {
		ended = dates.ExtendedUntil
	}
	return Lifecycle{State: Ended, Until: ended, Source: dates.Source,
		Note: fmt.Sprintf("End of life since %s: no more security fixes; upgrade to a supported release", describe(ended))}
}

// passed reports whether a date (YYYY-MM-DD, or YYYY-MM meaning the end of
// that month) is before today.
func passed(date, today string) bool {
	if len(date) == 7 {
		return date < today[:7]
	}
	return date < today
}

func describe(date string) string {
	layout := "2006-01-02"
	format := "2 January 2006"
	if len(date) == 7 {
		layout, format = "2006-01", "January 2006"
	}
	if parsed, err := time.Parse(layout, date); err == nil {
		return parsed.Format(format)
	}
	return date
}

// Fedora reads a Fedora release's state from Bodhi, Fedora's update system
// (https://bodhi.fedoraproject.org/releases/F44): "current" or "pending"
// releases get updates, "archived" ones are end of life.
func Fedora(data []byte, now time.Time) Lifecycle {
	var release struct {
		State string `json:"state"`
		EOL   string `json:"eol"`
	}
	source := "https://docs.fedoraproject.org/en-US/releases/lifecycle/"
	if err := json.Unmarshal(data, &release); err != nil {
		return Lifecycle{State: Unknown, Note: "Check Fedora's release lifecycle", Source: source}
	}
	eol := strings.TrimSpace(release.EOL)
	if len(eol) > 10 {
		eol = eol[:10]
	}
	if release.State == "archived" || (eol != "" && passed(eol, now.UTC().Format("2006-01-02"))) {
		note := "End of life: no more security fixes; upgrade to a supported Fedora release"
		if eol != "" {
			note = "End of life since " + describe(eol) + ": no more security fixes; upgrade to a supported Fedora release"
		}
		return Lifecycle{State: Ended, Until: eol, Source: source, Note: note}
	}
	if eol != "" {
		return Lifecycle{State: Supported, Until: eol, Source: source, Note: "Security fixes until " + describe(eol)}
	}
	return Lifecycle{State: Supported, Source: source, Note: "A current Fedora release"}
}
