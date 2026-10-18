package scanner

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/advisory"
	"deaconguard/internal/inventory"
	"deaconguard/internal/lifecycle"
	"deaconguard/internal/platform"
)

const maxInventoryBytes = 32 << 20

type Report struct {
	OS               string                 `json:"os"`
	ScannedAt        string                 `json:"scanned_at"`
	FindingCount     int                    `json:"finding_count"`
	Findings         []advisory.Finding     `json:"findings"`
	UnsupportedCount int                    `json:"unsupported_count"`
	Unsupported      []advisory.Unsupported `json:"unsupported_cves"`
	// FixCounts counts findings by what clears them; see advisory.Classify.
	FixCounts        map[string]int        `json:"fix_counts"`
	Coverage         string                `json:"coverage"`
	AdvisoryDatabase advisory.FeedMetadata `json:"advisory_database"`
	// Lifecycle says whether the release still gets security fixes.
	Lifecycle lifecycle.Lifecycle `json:"lifecycle"`
	// ExploitData is the KEV and EPSS data the findings were marked with.
	ExploitData    advisory.ExploitData `json:"exploit_data"`
	Maintenance    string               `json:"maintenance"`
	PackageManager string               `json:"package_manager"`
	PackageCount   int                  `json:"package_count"`
	// InstalledPackages and Distro are kept for the scan's SBOM; the scan
	// report the UI and API show leaves the package list out.
	InstalledPackages []InstalledPackage `json:"installed_packages,omitempty"`
	Distro            Distro             `json:"distro"`
	Evaluator         string             `json:"evaluator"`
}

// InstalledPackage is one installed OS package, as the package manager names it.
type InstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"`
}

// Distro is the distribution's ID and version from /etc/os-release.
type Distro struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
}

func Scan(osRelease, dpkgStatus, rpmQuery, kernel string, client *http.Client, now time.Time) (Report, error) {
	if len(osRelease) == 0 || len(osRelease) > 16*1024 {
		return Report{}, fmt.Errorf("OS release inventory is missing or exceeds 16 KiB")
	}
	target, err := platform.Detect(osRelease)
	if err != nil {
		return Report{}, err
	}
	packages := make([]inventory.Package, 0)
	packageManager := "dpkg"
	if target.Family == platform.Ubuntu || target.Family == platform.Debian {
		if len(dpkgStatus) == 0 || len(dpkgStatus) > maxInventoryBytes {
			return Report{}, fmt.Errorf("dpkg inventory is missing or exceeds 32 MiB")
		}
		packages, err = inventory.ParseDPKGStatus(dpkgStatus)
	} else {
		packageManager = "rpm"
		if len(rpmQuery) == 0 || len(rpmQuery) > maxInventoryBytes {
			return Report{}, fmt.Errorf("RPM inventory is missing or exceeds 32 MiB")
		}
		packages, err = inventory.ParseRPMQuery(rpmQuery)
	}
	if err != nil {
		return Report{}, err
	}
	if len(kernel) == 0 || len(kernel) > 256 {
		return Report{}, fmt.Errorf("running kernel release is missing or invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var evaluation advisory.DebianEvaluation
	var feed advisory.Feed
	assumedSigned := false
	switch target.Family {
	case platform.Ubuntu:
		feed, err = advisory.LoadUbuntuOVAL(target, client, now)
		if err == nil {
			evaluation, err = advisory.EvaluateUbuntuOVAL(feed.Data, target, packages, kernel)
		}
	case platform.Debian:
		feed, err = advisory.LoadDebianTracker(target, client, now)
		if err == nil {
			evaluation, err = advisory.EvaluateDebian(target, packages, feed.Data)
		}
	case platform.AmazonLinux:
		feed, err = advisory.LoadAmazonLinux2023RSS(target, client, now)
		if err == nil {
			evaluation, err = advisory.EvaluateAmazonLinux2023(target, packages, feed.Data, client)
		}
	case platform.RHEL:
		feed, err = advisory.LoadRedHatOVAL(target, client, now)
		if err == nil {
			evaluation, err = advisory.EvaluateRedHatOVAL(feed.Data, packages)
		}
	case platform.Alma, platform.Oracle, platform.OpenSUSELeap, platform.SLES:
		feed, err = advisory.LoadFamilyOVAL(target, client, now)
		if err == nil {
			var family advisory.FamilyEvaluation
			family, err = advisory.EvaluateFamilyOVAL(target, feed.Data, packages)
			evaluation, assumedSigned = family.DebianEvaluation, family.AssumedSigned
		}
	case platform.Rocky, platform.Fedora:
		evaluation, feed.Metadata, err = advisory.LoadUpdateInfo(target, packages, client, now)
	default:
		return Report{}, fmt.Errorf("no advisory evaluator for %s", target.Family)
	}
	if err != nil {
		return Report{}, fmt.Errorf("scan %s %s advisory data: %w", target.Family, target.VersionID, err)
	}
	advisory.Classify(evaluation.Findings, target.Family, packages, kernel)
	exploitData := advisory.Enrich(evaluation.Findings, client, now)
	fixCounts := make(map[string]int, len(advisory.FixStates))
	for _, state := range advisory.FixStates {
		fixCounts[state] = 0
	}
	for _, finding := range evaluation.Findings {
		fixCounts[finding.Fix]++
	}
	life := releaseLifecycle(target, client, now)
	return Report{
		FixCounts:         fixCounts,
		OS:                PlatformName(target),
		ScannedAt:         now.UTC().Format(time.RFC3339),
		FindingCount:      len(evaluation.Findings),
		Findings:          evaluation.Findings,
		UnsupportedCount:  len(evaluation.Unsupported),
		Unsupported:       evaluation.Unsupported,
		Coverage:          coverage(target.Family, assumedSigned),
		Lifecycle:         life,
		AdvisoryDatabase:  feed.Metadata,
		ExploitData:       exploitData,
		Maintenance:       life.Note,
		PackageManager:    packageManager,
		Evaluator:         "DeaconGuard Go scanner",
		PackageCount:      len(packages),
		InstalledPackages: installedPackages(packages),
		Distro:            Distro{ID: target.ID, VersionID: target.VersionID},
	}, nil
}

func installedPackages(packages []inventory.Package) []InstalledPackage {
	installed := make([]InstalledPackage, 0, len(packages))
	for _, p := range packages {
		source := p.Source
		if source == p.Name {
			source = ""
		}
		installed = append(installed, InstalledPackage{Name: p.Name, Version: p.Version, Arch: p.Arch, Source: source})
	}
	sort.Slice(installed, func(i, j int) bool {
		if installed[i].Name != installed[j].Name {
			return installed[i].Name < installed[j].Name
		}
		return installed[i].Arch < installed[j].Arch
	})
	return installed
}

// PlatformName is the display name of a detected platform, such as "Ubuntu 24.04 LTS".
func PlatformName(target platform.Platform) string {
	switch target.Family {
	case platform.Ubuntu:
		return "Ubuntu " + target.VersionID + " LTS"
	case platform.Debian:
		return "Debian " + target.VersionID + " (" + target.Codename + ")"
	case platform.AmazonLinux:
		return "Amazon Linux " + target.VersionID
	case platform.RHEL:
		return "Red Hat Enterprise Linux " + target.VersionID
	case platform.Rocky:
		return "Rocky Linux " + target.VersionID
	case platform.Alma:
		return "AlmaLinux " + target.VersionID
	case platform.Oracle:
		return "Oracle Linux " + target.VersionID
	case platform.Fedora:
		return "Fedora " + target.VersionID
	case platform.OpenSUSELeap:
		return "openSUSE Leap " + target.VersionID
	case platform.SLES:
		if target.Major == 15 {
			return fmt.Sprintf("SUSE Linux Enterprise 15 SP%d", target.Minor)
		}
		return "SUSE Linux Enterprise " + target.VersionID
	default:
		return strings.ToUpper(string(target.Family)) + " " + target.VersionID
	}
}

func coverage(family platform.Family, assumedSigned bool) string {
	text := ""
	switch family {
	case platform.Ubuntu:
		text = "Canonical CVE OVAL package and kernel rules; unsupported rules are listed, not reported clean"
	case platform.Debian:
		text = "Debian Security Tracker CVE status and fixed versions for installed source packages"
	case platform.AmazonLinux:
		text = "Amazon Linux 2023 ALAS RSS and bulletin replacement packages matching installed RPMs"
	case platform.RHEL:
		text = "Red Hat RHEL OVAL RPM checks; unsupported rules are listed, not reported clean"
	case platform.Alma:
		text = "AlmaLinux OVAL errata for packages signed by AlmaLinux; unsupported rules are listed, not reported clean"
	case platform.Oracle:
		text = "Oracle Linux OVAL errata (ELSA) for packages signed by Oracle; unsupported rules are listed, not reported clean"
	case platform.OpenSUSELeap, platform.SLES:
		text = "SUSE OVAL CVE rules for packages signed by SUSE or openSUSE; unsupported rules are listed, not reported clean"
	case platform.Rocky:
		text = "Rocky Linux security errata (updateinfo) from the BaseOS and AppStream repositories"
	case platform.Fedora:
		text = "Fedora security updates (updateinfo) from the updates repository"
	default:
		return "No advisory coverage"
	}
	if assumedSigned {
		text += ". The agent is older than 0.19.0 and doesn't report who signed each package, so all were taken to be the distribution's"
	}
	return text
}

// releaseLifecycle says whether target still gets security fixes: from
// Fedora's release data, or the published dates.
func releaseLifecycle(target platform.Platform, client *http.Client, now time.Time) lifecycle.Lifecycle {
	if target.Family == platform.Fedora {
		feed, err := advisory.LoadFeed(fmt.Sprintf("https://bodhi.fedoraproject.org/releases/F%d", target.Major), fmt.Sprintf("fedora-%d-release", target.Major), client, now)
		if err != nil {
			return lifecycle.Lifecycle{State: lifecycle.Unknown, Note: "Check Fedora's release lifecycle: Fedora's release data could not be read"}
		}
		return lifecycle.Fedora(feed.Data, now)
	}
	return lifecycle.Of(target, now)
}
