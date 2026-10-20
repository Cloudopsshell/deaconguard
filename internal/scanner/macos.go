package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/advisory"
	"deaconguard/internal/lifecycle"
	"deaconguard/internal/platform"
)

// macOSReleases is endoflife.date's list of macOS releases: each one's
// latest version and whether Apple still ships security updates for it.
const macOSReleases = "https://endoflife.date/api/macos.json"

// appleSecurityReleases is Apple's list of security updates, with what each
// fixes.
const appleSecurityReleases = "https://support.apple.com/en-us/100100"

type macOSCycle struct {
	Cycle    string `json:"cycle"`
	Codename string `json:"codename"`
	EOL      any    `json:"eol"`
	Latest   string `json:"latest"`
}

// macOSCycleOf is the release a version belongs to: 27 for 27.0.1, and
// 10.15 for 10.15.7.
func macOSCycleOf(version string) string {
	fields := strings.Split(version, ".")
	if fields[0] == "10" && len(fields) > 1 {
		return "10." + fields[1]
	}
	return fields[0]
}

// compareVersions compares dotted versions number by number; missing parts
// count as 0, so 27.0 equals 27.0.0.
func compareVersions(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(left) || i < len(right); i++ {
		var x, y int
		if i < len(left) {
			x, _ = strconv.Atoi(left[i])
		}
		if i < len(right) {
			y, _ = strconv.Atoi(right[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// evaluateMacOS checks a Mac's release against Apple's: whether it still
// gets security updates, and whether a newer version of it is out. Apple
// publishes what each update fixes, but not in a form to match against
// installed software, so the findings are the updates themselves.
func evaluateMacOS(target platform.Platform, softwareUpdates string, data []byte, now time.Time) ([]advisory.Finding, lifecycle.Lifecycle) {
	var cycles []macOSCycle
	life := lifecycle.Lifecycle{State: lifecycle.Unknown, Source: "https://endoflife.date/macos",
		Note: "Apple doesn't publish end-of-life dates; endoflife.date's list of macOS releases couldn't be read"}
	var findings []advisory.Finding
	cycleName := macOSCycleOf(target.VersionID)
	if err := json.Unmarshal(data, &cycles); err == nil {
		for _, cycle := range cycles {
			if cycle.Cycle != cycleName {
				continue
			}
			name := strings.TrimSpace("macOS " + cycle.Cycle + " " + cycle.Codename)
			switch eol := cycle.EOL.(type) {
			case bool:
				if eol {
					life = lifecycle.Lifecycle{State: lifecycle.Ended, Source: life.Source,
						Note: name + " no longer gets security updates from Apple. Upgrade to a current macOS release."}
				} else {
					life = lifecycle.Lifecycle{State: lifecycle.Supported, Source: life.Source,
						Note: name + " gets security updates from Apple. Apple supports about the three newest releases; it announces no end date."}
				}
			case string:
				ended, err := time.Parse("2006-01-02", eol)
				if err == nil && !now.Before(ended) {
					life = lifecycle.Lifecycle{State: lifecycle.Ended, Until: eol, Source: life.Source,
						Note: fmt.Sprintf("%s stopped getting security updates from Apple around %s. Upgrade to a current macOS release.", name, eol)}
				} else {
					life = lifecycle.Lifecycle{State: lifecycle.Supported, Until: eol, Source: life.Source, Note: name + " gets security updates from Apple."}
				}
			}
			if cycle.Latest != "" && compareVersions(target.VersionID, cycle.Latest) < 0 {
				findings = append(findings, advisory.Finding{
					ID: "MACOS-" + cycle.Latest, Package: "macOS", InstalledVersion: target.VersionID, FixedVersion: cycle.Latest,
					Severity: "HIGH", Fix: advisory.FixAvailable, URL: appleSecurityReleases,
					Title: fmt.Sprintf("macOS %s is out; this Mac runs %s. Apple's updates fix security flaws, some exploited before the fix; install it in System Settings → General → Software Update.", cycle.Latest, target.VersionID),
				})
			}
		}
	}
	for _, update := range parseSoftwareUpdates(softwareUpdates) {
		if strings.HasPrefix(update.title, "macOS") && len(findings) > 0 && findings[0].FixedVersion == update.version {
			continue
		}
		severity := "MEDIUM"
		lower := strings.ToLower(update.title)
		if strings.Contains(lower, "macos") || strings.Contains(lower, "security") || strings.Contains(lower, "safari") || strings.Contains(lower, "xprotect") {
			severity = "HIGH"
		}
		findings = append(findings, advisory.Finding{
			ID: "UPDATE-" + strings.ReplaceAll(update.label, " ", "-"), Package: update.title, FixedVersion: update.version,
			Severity: severity, Fix: advisory.FixAvailable, URL: appleSecurityReleases,
			Title: fmt.Sprintf("%s %s is ready to install on this Mac%s.", update.title, update.version, update.action),
		})
	}
	if findings == nil {
		findings = []advisory.Finding{}
	}
	return findings, life
}

type softwareUpdate struct {
	label, title, version, action string
}

// parseSoftwareUpdates reads `softwareupdate --list` output:
//
//   - Label: macOS Tahoe 26.7.2-26H123
//     Title: macOS Tahoe 26.7.2, Version: 26.7.2, Size: 3600000KiB, Recommended: YES, Action: restart,
func parseSoftwareUpdates(output string) []softwareUpdate {
	var updates []softwareUpdate
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if label, found := strings.CutPrefix(line, "* Label:"); found {
			updates = append(updates, softwareUpdate{label: strings.TrimSpace(label)})
			continue
		}
		if !strings.HasPrefix(line, "Title:") || len(updates) == 0 {
			continue
		}
		current := &updates[len(updates)-1]
		for _, field := range strings.Split(line, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(field), ":")
			value = strings.TrimSpace(value)
			switch name {
			case "Title":
				current.title = value
			case "Version":
				current.version = value
			case "Action":
				if value == "restart" {
					current.action = "; it restarts the Mac"
				}
			}
		}
	}
	kept := updates[:0]
	for _, update := range updates {
		if update.title == "" {
			update.title = update.label
		}
		if len(kept) < 50 {
			kept = append(kept, update)
		}
	}
	return kept
}

// ScanMacOS is Scan for a Mac: osRelease is made from sw_vers, and
// softwareUpdates is what `softwareupdate --list --no-scan` printed.
func ScanMacOS(osRelease, softwareUpdates string, client *http.Client, now time.Time) (Report, error) {
	target, err := platform.Detect(osRelease)
	if err != nil {
		return Report{}, err
	}
	if target.Family != platform.MacOS {
		return Report{}, fmt.Errorf("%s isn't macOS", target.ID)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// Without Apple's release list a Mac can't be judged; it isn't reported clean.
	feed, err := advisory.LoadFeed(macOSReleases, "macos-releases", client, now)
	if err != nil {
		return Report{}, fmt.Errorf("read the list of macOS releases: %w", err)
	}
	findings, life := evaluateMacOS(target, softwareUpdates, feed.Data, now)
	fixCounts := make(map[string]int, len(advisory.FixStates))
	for _, state := range advisory.FixStates {
		fixCounts[state] = 0
	}
	fixCounts[advisory.FixAvailable] = len(findings)
	return Report{
		OS: PlatformName(target), ScannedAt: now.UTC().Format(time.RFC3339),
		FindingCount: len(findings), Findings: findings, Unsupported: []advisory.Unsupported{},
		FixCounts: fixCounts, Lifecycle: life, Maintenance: life.Note, AdvisoryDatabase: feed.Metadata,
		Coverage:       coverage(platform.MacOS, false),
		PackageManager: "softwareupdate", Evaluator: "DeaconGuard Go scanner",
		Distro: Distro{ID: target.ID, VersionID: target.VersionID},
	}, nil
}
