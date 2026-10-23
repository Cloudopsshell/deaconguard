package lifecycle

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/platform"
)

// Retired is a release DeaconGuard doesn't check because it no longer gets
// security fixes: its vendor publishes no advisories for it any more, so a
// package check would find little and prove nothing.
type Retired struct {
	// Name is the release, such as "Debian 10 (buster)".
	Name string
	// Lifecycle is Ended, with the date and the vendor's lifecycle page.
	Lifecycle Lifecycle
	// Distribution and Version name it for a finding ("debian", "10
	// (buster)"); Upgrade is the release to move to ("13 (trixie)").
	Distribution, Version, Upgrade string
}

// retiredDebian are Debian releases with the end of their LTS, the last
// security fixes anyone publishes for them.
var retiredDebian = map[int]struct{ codename, ended string }{
	7: {"wheezy", "2018-05-31"}, 8: {"jessie", "2020-06-30"}, 9: {"stretch", "2022-06-30"},
	10: {"buster", "2024-06-30"}, 11: {"bullseye", "2026-08-31"},
}

// retiredAlpine are Alpine branches before 3.18, from
// https://alpinelinux.org/releases.json; older ones ended before 2022.
var retiredAlpine = map[int]string{
	12: "2022-05-01", 13: "2022-11-01", 14: "2023-05-01", 15: "2023-11-01", 16: "2024-05-23", 17: "2024-11-22",
}

// RetiredRelease reports whether an os-release names a release that has
// ended and that DeaconGuard therefore doesn't check: Debian 11 and
// earlier, Alpine before 3.18, CentOS Linux, CentOS Stream 8, Amazon Linux
// 2, openSUSE Leap before 15.6 and Fedora before 40.
func RetiredRelease(osRelease string, now time.Time) (Retired, bool) {
	values, err := platform.ParseOSRelease(osRelease)
	if err != nil {
		return Retired{}, false
	}
	id, version := strings.ToLower(values["ID"]), values["VERSION_ID"]
	major, minor := numbers(version)
	var r Retired
	ended, source := "", ""
	switch {
	case id == "debian" && major >= 1 && major <= 11:
		release := retiredDebian[major]
		r = Retired{Name: fmt.Sprintf("Debian %d", major), Distribution: "debian", Version: strconv.Itoa(major), Upgrade: newestDebian()}
		if release.codename != "" {
			r.Name += " (" + release.codename + ")"
			r.Version += " (" + release.codename + ")"
		}
		ended, source = release.ended, "https://wiki.debian.org/LTS"
	case id == "alpine" && major == 3 && minor < 18:
		r = Retired{Name: fmt.Sprintf("Alpine Linux %d.%d", major, minor), Distribution: "alpine", Version: fmt.Sprintf("%d.%d", major, minor), Upgrade: newestAlpine(now)}
		ended, source = retiredAlpine[minor], "https://alpinelinux.org/releases/"
	case id == "centos" && (major == 7 || major == 8):
		name := values["NAME"]
		r = Retired{Name: fmt.Sprintf("CentOS Linux %d", major), Distribution: "centos", Version: strconv.Itoa(major), Upgrade: "Rocky Linux or AlmaLinux 9"}
		ended = map[int]string{7: "2024-06-30", 8: "2021-12-31"}[major]
		if strings.Contains(strings.ToLower(name), "stream") {
			if major != 8 {
				return Retired{}, false
			}
			r.Name, ended = "CentOS Stream 8", "2024-05-31"
		}
		source = "https://www.centos.org/centos-linux-eol/"
	case id == "amzn" && version == "2":
		r = Retired{Name: "Amazon Linux 2", Distribution: "amzn", Version: "2", Upgrade: "2023"}
		ended, source = "2026-06-30", "https://aws.amazon.com/amazon-linux-2/faqs/"
	case id == "opensuse-leap" && major == 15 && minor < 6:
		r = Retired{Name: "openSUSE Leap " + version, Distribution: "opensuse-leap", Version: version, Upgrade: "16.0"}
		ended = map[int]string{3: "2022-12-31", 4: "2023-12-07", 5: "2024-12-31"}[minor]
		source = "https://en.opensuse.org/Lifetime"
	case id == "fedora" && major >= 1 && major < 40:
		r = Retired{Name: fmt.Sprintf("Fedora %d", major), Distribution: "fedora", Version: strconv.Itoa(major), Upgrade: "the newest Fedora"}
		ended, source = map[int]string{38: "2024-05-21", 39: "2024-11-26"}[major], "https://fedorapeople.org/groups/schedule/"
	default:
		return Retired{}, false
	}
	today := now.UTC().Format("2006-01-02")
	if ended != "" && !passed(ended, today) {
		return Retired{}, false
	}
	r.Lifecycle = Lifecycle{State: Ended, Until: ended, Source: source, Note: "End of life: no more security fixes; upgrade to a supported release"}
	if ended != "" {
		r.Lifecycle.Note = fmt.Sprintf("End of life since %s: no more security fixes; upgrade to a supported release", describe(ended))
	}
	return r, true
}

// Explain says what a retired release means and what to do, in one
// sentence, for a scan's error or a finding's detail.
func (r Retired) Explain() string {
	when := "has reached end of life"
	if r.Lifecycle.Until != "" {
		when = "reached end of life on " + describe(r.Lifecycle.Until)
	}
	return fmt.Sprintf("%s %s and gets no security fixes, so its packages can't be checked against advisories; upgrade to %s.", r.Name, when, r.upgradeName())
}

func (r Retired) upgradeName() string {
	switch r.Distribution {
	case "debian":
		return "Debian " + r.Upgrade
	case "alpine":
		return "Alpine Linux " + r.Upgrade
	case "amzn":
		return "Amazon Linux " + r.Upgrade
	case "opensuse-leap":
		return "openSUSE Leap " + r.Upgrade
	}
	return r.Upgrade
}

func numbers(version string) (int, int) {
	fields := strings.Split(version, ".")
	major, _ := strconv.Atoi(fields[0])
	minor := 0
	if len(fields) > 1 {
		minor, _ = strconv.Atoi(fields[1])
	}
	return major, minor
}

// newestDebian is the newest Debian release DeaconGuard knows.
func newestDebian() string {
	newest := 0
	for release := range releases[platform.Debian] {
		if major, _ := strconv.Atoi(release); major > newest {
			newest = major
		}
	}
	codename := map[int]string{12: "bookworm", 13: "trixie"}[newest]
	if codename == "" {
		return strconv.Itoa(newest)
	}
	return fmt.Sprintf("%d (%s)", newest, codename)
}

// newestAlpine is the newest Alpine branch DeaconGuard knows that is still
// supported at now.
func newestAlpine(now time.Time) string {
	today := now.UTC().Format("2006-01-02")
	best, bestMinor := "", -1
	for branch, dates := range releases[platform.Alpine] {
		_, minor := numbers(branch)
		if minor > bestMinor && !passed(dates.Regular, today) {
			best, bestMinor = branch, minor
		}
	}
	if best == "" {
		return "a supported release"
	}
	return best
}
