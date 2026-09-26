package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"opsarmor/internal/advisory"
	"opsarmor/internal/inventory"
	"opsarmor/internal/platform"
)

const maxInventoryBytes = 32 << 20

type Report struct {
	OS               string                 `json:"os"`
	ScannedAt        string                 `json:"scanned_at"`
	FindingCount     int                    `json:"finding_count"`
	Findings         []advisory.Finding     `json:"findings"`
	UnsupportedCount int                    `json:"unsupported_count"`
	Unsupported      []advisory.Unsupported `json:"unsupported_cves"`
	Coverage         string                 `json:"coverage"`
	AdvisoryDatabase advisory.FeedMetadata  `json:"advisory_database"`
	Maintenance      string                 `json:"maintenance"`
	PackageManager   string                 `json:"package_manager"`
	PackageCount     int                    `json:"package_count"`
	Evaluator        string                 `json:"evaluator"`
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
	default:
		return Report{}, fmt.Errorf("no advisory evaluator for %s", target.Family)
	}
	if err != nil {
		return Report{}, fmt.Errorf("scan %s %s advisory data: %w", target.Family, target.VersionID, err)
	}
	return Report{
		OS:               PlatformName(target),
		ScannedAt:        now.UTC().Format(time.RFC3339),
		FindingCount:     len(evaluation.Findings),
		Findings:         evaluation.Findings,
		UnsupportedCount: len(evaluation.Unsupported),
		Unsupported:      evaluation.Unsupported,
		Coverage:         coverage(target.Family),
		AdvisoryDatabase: feed.Metadata,
		Maintenance:      maintenance(target),
		PackageManager:   packageManager,
		Evaluator:        "OpsArmor Go scanner",
		PackageCount:     len(packages),
	}, nil
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
	default:
		return strings.ToUpper(string(target.Family)) + " " + target.VersionID
	}
}

func coverage(family platform.Family) string {
	switch family {
	case platform.Ubuntu:
		return "Canonical CVE OVAL package and kernel rules; unsupported rules are listed, not reported clean"
	case platform.Debian:
		return "Debian Security Tracker CVE status and fixed versions for installed source packages"
	case platform.AmazonLinux:
		return "Amazon Linux 2023 ALAS RSS and bulletin replacement packages matching installed RPMs"
	case platform.RHEL:
		return "Red Hat RHEL OVAL RPM checks; unsupported rules are listed, not reported clean"
	default:
		return "No advisory coverage"
	}
}

func maintenance(target platform.Platform) string {
	if target.Family == platform.Ubuntu && (target.VersionID == "18.04" || target.VersionID == "20.04") {
		return "Check Ubuntu Pro/ESM entitlement; OpsArmor does not verify entitlement"
	}
	if target.Family == platform.Debian {
		return "Debian stable security status; verify Debian LTS/ELTS coverage for older packages"
	}
	return "Consult the distribution lifecycle and support policy"
}
