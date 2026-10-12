// Package report turns an audit or a scan into a report a client can keep:
// PDF, HTML, Excel, CSV or JSON. Every format is rendered from one frozen
// snapshot, so they always agree, and the snapshot's SHA-256 fingerprint
// lets anyone check a report against the server that made it.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
	"deaconguard/internal/compliance"
	"deaconguard/internal/store"
)

// Branding is what an admin set for every report: the company that prepares
// them, a contact line, and a logo.
type Branding struct {
	Company string `json:"company"`
	Contact string `json:"contact"`
	// Logo is a PNG or JPEG image, at most MaxLogoBytes.
	Logo     []byte `json:"logo,omitempty"`
	LogoType string `json:"logo_type,omitempty"`
}

// MaxLogoBytes bounds the logo, which every report carries.
const MaxLogoBytes = 256 << 10

// Report is the frozen content of one report.
type Report struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // "audit" or "scan"
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
	Branding    Branding  `json:"branding"`
	Client      string    `json:"client"`
	Notes       string    `json:"notes"`

	Host       string     `json:"host"`
	HostID     string     `json:"host_id"`
	OS         string     `json:"os"`
	ScanID     string     `json:"scan_id"`
	StartedAt  string     `json:"started_at"`
	FinishedAt string     `json:"finished_at"`
	Checks     []string   `json:"checks"`
	Generator  string     `json:"generator"`
	Audit      *AuditPart `json:"audit,omitempty"`

	Comparison      *Comparison          `json:"comparison,omitempty"`
	Policies        []audit.PolicyResult `json:"policies,omitempty"`
	Compliance      []compliance.Result  `json:"compliance,omitempty"`
	Packages        *store.FixSummary    `json:"packages,omitempty"`
	Severity        store.SeverityCounts `json:"severity"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
	CheckResults    []CheckPart          `json:"check_results"`
	Inventory       *checks.Inventory    `json:"inventory,omitempty"`
}

// AuditPart is the graded part of an audit's report.
type AuditPart struct {
	Grade      string           `json:"grade"`
	Score      int              `json:"score"`
	Caps       []string         `json:"caps"`
	Incomplete []string         `json:"incomplete"`
	Counts     audit.Counts     `json:"counts"`
	Categories []audit.Category `json:"categories"`
	Controls   []audit.Control  `json:"controls"`
}

// Vulnerability is one package finding.
type Vulnerability struct {
	ID        string `json:"id"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Severity  string `json:"severity"`
	Fix       string `json:"fix"`
	Title     string `json:"title"`
}

// CheckPart is the result of one check other than packages and hardening.
type CheckPart struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Status   string           `json:"status"`
	Summary  string           `json:"summary"`
	Findings []checks.Finding `json:"findings"`
	Notes    []string         `json:"notes"`
}

// Comparison sets an audit against an earlier one of the same host.
type Comparison struct {
	ScanID       string   `json:"scan_id"`
	Date         string   `json:"date"`
	Grade        string   `json:"grade"`
	Score        int      `json:"score"`
	Fixed        []string `json:"fixed"`         // controls that failed then and pass now
	NewFailures  []string `json:"new_failures"`  // controls that pass then or didn't apply, and fail now
	CriticalThen int      `json:"critical_then"` // fixable critical vulnerabilities then
	HighThen     int      `json:"high_then"`
}

// Source is everything a report is built from.
type Source struct {
	ID          string
	Scan        store.Scan
	Host        store.Host
	Report      map[string]any
	Summary     *audit.Summary
	Base        *store.Scan
	BaseSummary *audit.Summary
	// Frameworks to include a compliance mapping for.
	Frameworks []string
	Branding   Branding
	Client     string
	Notes      string
	By         string
	Now        time.Time
	Version    string
}

// Build freezes a report.
func Build(source Source) (Report, error) {
	report := Report{
		ID: source.ID, Kind: "scan", GeneratedAt: source.Now.UTC().Truncate(time.Second), GeneratedBy: source.By,
		Branding: source.Branding, Client: strings.TrimSpace(source.Client), Notes: strings.TrimSpace(source.Notes),
		Host: source.Host.Address, HostID: source.Host.ID, OS: source.Scan.OS, ScanID: source.Scan.ID,
		StartedAt: source.Scan.StartedAt, Checks: source.Scan.Checks, Generator: "DeaconGuard " + source.Version,
		Packages: source.Scan.Fixes, Severity: source.Scan.Severity, Vulnerabilities: []Vulnerability{}, CheckResults: []CheckPart{},
	}
	if source.Scan.FinishedAt != nil {
		report.FinishedAt = *source.Scan.FinishedAt
	}
	if summary := source.Summary; summary != nil {
		report.Kind = "audit"
		report.Audit = &AuditPart{Grade: summary.Grade, Score: summary.Score, Caps: summary.Caps, Incomplete: summary.Incomplete,
			Counts: summary.Counts, Categories: summary.Categories, Controls: summary.Controls}
		report.Inventory = summary.Inventory
		report.Policies = summary.Policies
		for _, id := range source.Frameworks {
			if framework, found := compliance.Find(id); found {
				report.Compliance = append(report.Compliance, compliance.Evaluate(*summary, framework))
			}
		}
		if source.Base != nil && source.BaseSummary != nil {
			report.Comparison = compare(*source.Base, *source.BaseSummary, *summary)
		}
	}

	if raw, ok := source.Report["findings"]; ok {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return Report{}, err
		}
		var findings []struct {
			ID, Package, Severity, Fix, Title string
			Installed                         string `json:"installed_version"`
			Fixed                             string `json:"fixed_version"`
		}
		if err := json.Unmarshal(encoded, &findings); err != nil {
			return Report{}, fmt.Errorf("read the vulnerabilities: %w", err)
		}
		for _, finding := range findings {
			report.Vulnerabilities = append(report.Vulnerabilities, Vulnerability{ID: finding.ID, Package: finding.Package,
				Installed: finding.Installed, Fixed: finding.Fixed, Severity: strings.ToUpper(finding.Severity), Fix: finding.Fix, Title: finding.Title})
		}
		sort.SliceStable(report.Vulnerabilities, func(a, b int) bool {
			left, right := report.Vulnerabilities[a], report.Vulnerabilities[b]
			if actionable(left.Fix) != actionable(right.Fix) {
				return actionable(left.Fix)
			}
			if severityRank[left.Severity] != severityRank[right.Severity] {
				return severityRank[left.Severity] < severityRank[right.Severity]
			}
			return left.ID < right.ID
		})
	}

	results := map[string]checks.Result{}
	if raw, ok := source.Report["check_results"]; ok {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return Report{}, err
		}
		if err := json.Unmarshal(encoded, &results); err != nil {
			return Report{}, fmt.Errorf("read the check results: %w", err)
		}
	}
	for _, definition := range checks.Definitions() {
		result, ran := results[definition.ID]
		if !ran || definition.ID == checks.Hardening {
			if ran && report.Inventory == nil {
				report.Inventory = result.Inventory
			}
			continue
		}
		part := CheckPart{ID: definition.ID, Name: definition.Name, Status: result.Status, Summary: result.Summary,
			Findings: result.Findings, Notes: result.Notes}
		if part.Findings == nil {
			part.Findings = []checks.Finding{}
		}
		if part.Notes == nil {
			part.Notes = []string{}
		}
		report.CheckResults = append(report.CheckResults, part)
	}
	return report, nil
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

// actionable: installing updates or restarting clears the finding.
func actionable(fix string) bool { return fix == "available" || fix == "reboot" }

func compare(base store.Scan, then, now audit.Summary) *Comparison {
	comparison := &Comparison{ScanID: base.ID, Date: base.StartedAt, Grade: then.Grade, Score: then.Score,
		Fixed: []string{}, NewFailures: []string{}}
	if then.Packages != nil {
		comparison.CriticalThen, comparison.HighThen = then.Packages.Actionable.Critical, then.Packages.Actionable.High
	}
	before := map[string]string{}
	for _, control := range then.Controls {
		before[control.ID] = control.Status
	}
	for _, control := range now.Controls {
		was := before[control.ID]
		switch {
		case was == checks.ControlFail && (control.Status == checks.ControlPass || control.Status == audit.Accepted):
			comparison.Fixed = append(comparison.Fixed, control.ID+" "+control.Title)
		case control.Status == checks.ControlFail && was != checks.ControlFail && was != "":
			comparison.NewFailures = append(comparison.NewFailures, control.ID+" "+control.Title)
		}
	}
	return comparison
}

// Snapshot encodes a report as stored; Fingerprint is its SHA-256.
func Snapshot(report Report) ([]byte, string, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(sum[:]), nil
}

// FormatFingerprint groups a fingerprint in fours, for people to compare.
func FormatFingerprint(fingerprint string) string {
	var groups []string
	for start := 0; start < len(fingerprint); start += 4 {
		groups = append(groups, fingerprint[start:min(start+4, len(fingerprint))])
	}
	return strings.Join(groups, " ")
}

// Title is the report's heading.
func (r Report) Title() string {
	if r.Kind == "audit" {
		return "Server audit report"
	}
	return "Security scan report"
}

// FileName is a download name such as deaconguard-audit-web-01-2026-10-12.pdf.
func (r Report) FileName(extension string) string {
	host := strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '.' {
			return character
		}
		return '-'
	}, r.Host)
	return fmt.Sprintf("deaconguard-%s-%s-%s.%s", r.Kind, host, r.GeneratedAt.Format("2006-01-02"), extension)
}

// FixLabel says in words what clears a vulnerability.
func FixLabel(fix string) string {
	switch fix {
	case "available":
		return "Update available"
	case "reboot":
		return "Fixed after a restart"
	case "old_kernel":
		return "Old kernel installed"
	case "ubuntu_pro":
		return "Fix in Ubuntu Pro"
	case "none":
		return "No fix yet"
	}
	return fix
}

// StatusLabel names a control status.
func StatusLabel(status string) string {
	switch status {
	case checks.ControlPass:
		return "Pass"
	case checks.ControlFail:
		return "Fail"
	case audit.Accepted:
		return "Accepted"
	case checks.ControlNA:
		return "Not applicable"
	}
	return "Not checked"
}

// RequirementLabel names a compliance requirement's status.
func RequirementLabel(status string) string {
	switch status {
	case compliance.Met:
		return "Met"
	case compliance.MetAccepted:
		return "Met, risk accepted"
	case compliance.NotMet:
		return "Not met"
	case compliance.NotChecked:
		return "Not checked"
	}
	return "Not applicable"
}
