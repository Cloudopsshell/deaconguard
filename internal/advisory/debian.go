package advisory

import (
	"encoding/json"
	"fmt"
	"strings"

	"opsarmor/internal/inventory"
	"opsarmor/internal/platform"
	"opsarmor/internal/version"
)

type Finding struct {
	ID               string `json:"id"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Severity         string `json:"severity"`
	URL              string `json:"url"`
	Title            string `json:"title"`
}

type Unsupported struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

type DebianEvaluation struct {
	Findings    []Finding
	Unsupported []Unsupported
	Evaluated   int
}

type debianTracker map[string]map[string]debianIssue

type debianIssue struct {
	Description string                  `json:"description"`
	Releases    map[string]debianStatus `json:"releases"`
}

type debianStatus struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

func EvaluateDebian(target platform.Platform, packages []inventory.Package, trackerJSON []byte) (DebianEvaluation, error) {
	if target.Family != platform.Debian {
		return DebianEvaluation{}, fmt.Errorf("Debian tracker cannot evaluate %s", target.Family)
	}
	var tracker debianTracker
	if err := json.Unmarshal(trackerJSON, &tracker); err != nil {
		return DebianEvaluation{}, fmt.Errorf("parse Debian Security Tracker data: %w", err)
	}
	if len(tracker) == 0 {
		return DebianEvaluation{}, fmt.Errorf("Debian Security Tracker data is empty")
	}

	result := DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}
	unsupportedIDs := make(map[string]bool)
	for _, installed := range packages {
		issues := tracker[installed.Source]
		for cve, issue := range issues {
			status, releaseFound := issue.Releases[target.Codename]
			if !releaseFound {
				continue
			}
			switch status.Status {
			case "resolved":
				result.Evaluated++
				if status.FixedVersion == "" || status.FixedVersion == "0" {
					continue
				}
				comparison, err := version.Debian(installed.Version, status.FixedVersion)
				if err != nil {
					return DebianEvaluation{}, fmt.Errorf("compare Debian package %s versions: %w", installed.Name, err)
				}
				if comparison < 0 {
					result.Findings = append(result.Findings, Finding{
						ID: cve, Package: installed.Name, InstalledVersion: installed.Version,
						FixedVersion: status.FixedVersion, Severity: debianSeverity(status.Urgency),
						URL: "https://security-tracker.debian.org/tracker/" + cve, Title: issue.Description,
					})
				}
			case "open", "no-dsa", "postponed":
				result.Evaluated++
				result.Findings = append(result.Findings, Finding{
					ID: cve, Package: installed.Name, InstalledVersion: installed.Version,
					Severity: debianSeverity(status.Urgency), URL: "https://security-tracker.debian.org/tracker/" + cve,
					Title: issue.Description,
				})
			case "undetermined", "ignored":
				if !unsupportedIDs[cve] {
					unsupportedIDs[cve] = true
					result.Unsupported = append(result.Unsupported, Unsupported{
						ID: cve, Title: issue.Description, Reason: "Debian tracker status is " + status.Status,
					})
				}
			case "not-affected":
				result.Evaluated++
			default:
				if !unsupportedIDs[cve] {
					unsupportedIDs[cve] = true
					result.Unsupported = append(result.Unsupported, Unsupported{
						ID: cve, Title: issue.Description, Reason: "unrecognized Debian tracker status " + status.Status,
					})
				}
			}
		}
	}
	return result, nil
}

func debianSeverity(urgency string) string {
	switch strings.ToLower(urgency) {
	case "emergency", "critical":
		return "CRITICAL"
	case "high", "urgent":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low", "unimportant":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
