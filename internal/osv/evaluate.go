package osv

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/advisory"
	"deaconguard/internal/checks"
	"deaconguard/internal/libraries"
)

// maxFindings matches what other checks list; the rest are counted in a note.
const maxFindings = 200

// evaluateTimeout bounds how long the server spends asking OSV for one scan.
const evaluateTimeout = 5 * time.Minute

// Evaluate checks the libraries the application library check found against
// OSV and sets the result's findings, summary and status. Findings an agent
// sent are discarded: the server decides what is vulnerable. When OSV can't
// be asked, the result fails rather than looking clean.
func Evaluate(result *checks.Result, client *Client, exploits advisory.HTTPClient, now time.Time) {
	result.Findings = []checks.Finding{}
	if result.Libraries == nil {
		if result.Status != checks.StatusFailed {
			result.Status, result.Error, result.Summary = checks.StatusFailed, "the host sent no library list", "Check could not run"
		}
		return
	}
	libs := result.Libraries.Libraries
	ctx, cancel := context.WithTimeout(context.Background(), evaluateTimeout)
	defer cancel()
	matches, err := client.Query(ctx, libs)
	if err != nil {
		result.Status = checks.StatusFailed
		result.Error = "Couldn't check the libraries against OSV: " + err.Error()
		result.Summary = fmt.Sprintf("Found %d libraries; not checked against OSV", len(libs))
		return
	}
	var ids []string
	for _, match := range matches {
		ids = append(ids, match.IDs...)
	}
	records, recordErr := client.Records(ctx, ids)
	if recordErr != nil {
		result.Notes = append(result.Notes, "Some OSV records couldn't be fetched, so their vulnerabilities aren't listed: "+recordErr.Error())
	}

	type found struct {
		finding  checks.Finding
		cve      string
		severity int
		library  libraries.Library
		record   Vulnerability
	}
	var all []found
	vulnerable := 0
	for _, match := range matches {
		listed := false
		for _, group := range aliasGroups(match.IDs, records) {
			record := group[0]
			severity := severityOfGroup(group)
			cve := cveOfGroup(group)
			all = append(all, found{
				finding: checks.Finding{
					Rule:     record.ID,
					Severity: severity,
					Title:    title(match.Library, record),
					Evidence: evidence(match.Library.Paths),
				},
				cve:      cve,
				severity: severityRank(severity),
				library:  match.Library,
				record:   record,
			})
			listed = true
		}
		if listed {
			vulnerable++
		}
	}

	// What CISA's KEV catalog and EPSS say about each CVE, as for packages.
	var withCVE []advisory.Finding
	for _, f := range all {
		if f.cve != "" {
			withCVE = append(withCVE, advisory.Finding{ID: f.cve, Severity: f.finding.Severity})
		}
	}
	exploitByCVE := make(map[string]*advisory.Exploit)
	if len(withCVE) > 0 {
		data := advisory.Enrich(withCVE, exploits, now)
		for _, f := range withCVE {
			exploitByCVE[f.ID] = f.Exploit
		}
		if !data.KEV.Available || !data.EPSS.Available {
			result.Notes = append(result.Notes, "Exploit data (CISA KEV or EPSS) wasn't available, so some vulnerabilities aren't marked as exploited or not.")
		}
	}
	exploitedCount := 0
	for index := range all {
		f := &all[index]
		exploit := exploitByCVE[f.cve]
		if exploit != nil && exploit.KEV {
			exploitedCount++
		}
		f.finding.Detail = detail(f.cve, f.record.ID, fixedVersions(f.record, f.library), exploit)
	}

	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		ak, bk := exploitByCVE[a.cve] != nil && exploitByCVE[a.cve].KEV, exploitByCVE[b.cve] != nil && exploitByCVE[b.cve].KEV
		if ak != bk {
			return ak
		}
		if a.severity != b.severity {
			return a.severity > b.severity
		}
		return a.finding.Title < b.finding.Title
	})
	for _, f := range all {
		result.Findings = append(result.Findings, f.finding)
	}
	if len(result.Findings) > maxFindings {
		result.Notes = append(result.Notes, fmt.Sprintf("%d more vulnerabilities were not listed.", len(result.Findings)-maxFindings))
		result.Findings = result.Findings[:maxFindings]
	}

	switch {
	case len(all) == 0:
		result.Summary = fmt.Sprintf("No known vulnerabilities in %d libraries", len(libs))
	default:
		result.Summary = fmt.Sprintf("%d vulnerabilities in %d of %d libraries", len(all), vulnerable, len(libs))
		if exploitedCount > 0 {
			result.Summary += fmt.Sprintf(", %d known to be exploited", exploitedCount)
		}
	}
	if result.Status == "" || result.Status == checks.StatusCompleted {
		result.Status = checks.StatusCompleted
		if recordErr != nil {
			result.Status = checks.StatusPartial
		}
	}
	if result.Notes == nil {
		result.Notes = []string{}
	}
}

// aliasGroups merges the records that describe the same vulnerability: OSV
// often lists one under several IDs, such as a GitHub advisory (GHSA) and a
// Python one (PYSEC) that name each other as aliases. Each group starts with
// the record to show, a GitHub advisory when there is one, since those have a
// summary and a severity. Withdrawn records are left out.
func aliasGroups(ids []string, records map[string]Vulnerability) [][]Vulnerability {
	var groups [][]Vulnerability
	names := make(map[string]int) // ID or alias -> group index
	for _, id := range ids {
		record, ok := records[id]
		if !ok || record.Withdrawn != "" {
			continue
		}
		group := -1
		for _, name := range append([]string{record.ID}, record.Aliases...) {
			if index, seen := names[name]; seen {
				group = index
				break
			}
		}
		if group < 0 {
			group = len(groups)
			groups = append(groups, nil)
		}
		groups[group] = append(groups[group], record)
		for _, name := range append([]string{record.ID}, record.Aliases...) {
			names[name] = group
		}
	}
	for _, group := range groups {
		sort.SliceStable(group, func(i, j int) bool { return showFirst(group[i]) && !showFirst(group[j]) })
	}
	return groups
}

func showFirst(record Vulnerability) bool {
	return strings.HasPrefix(record.ID, "GHSA-") && strings.TrimSpace(record.Summary) != ""
}

// severityOfGroup is the highest severity any record of the group gives.
func severityOfGroup(group []Vulnerability) string {
	best := "UNKNOWN"
	for _, record := range group {
		if severity := severityOf(record); severityRank(severity) > severityRank(best) {
			best = severity
		}
	}
	return best
}

func cveOfGroup(group []Vulnerability) string {
	for _, record := range group {
		if cve := cveOf(record); cve != "" {
			return cve
		}
	}
	return ""
}

// severityOf takes the severity the record's source gave (GitHub's
// advisories use LOW, MODERATE, HIGH and CRITICAL), or else computes it from
// a CVSS v3 vector.
func severityOf(record Vulnerability) string {
	if value, ok := record.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(value) {
		case "CRITICAL":
			return "CRITICAL"
		case "HIGH":
			return "HIGH"
		case "MODERATE", "MEDIUM":
			return "MEDIUM"
		case "LOW":
			return "LOW"
		}
	}
	for _, severity := range record.Severity {
		if severity.Type == "CVSS_V3" {
			if score, ok := cvss3BaseScore(severity.Score); ok {
				return severityOfScore(score)
			}
		}
	}
	return "UNKNOWN"
}

func severityRank(severity string) int {
	return map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[severity]
}

func cveOf(record Vulnerability) string {
	if strings.HasPrefix(record.ID, "CVE-") {
		return record.ID
	}
	for _, alias := range record.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return ""
}

// fixedVersions lists the versions the record says fix the library.
func fixedVersions(record Vulnerability, library libraries.Library) []string {
	seen := make(map[string]bool)
	var fixed []string
	for _, affected := range record.Affected {
		if affected.Package.Ecosystem != library.Ecosystem || !sameName(library.Ecosystem, affected.Package.Name, library.Name) {
			continue
		}
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if version := event["fixed"]; version != "" && !seen[version] && r.Type != "GIT" {
					seen[version] = true
					fixed = append(fixed, version)
				}
			}
		}
	}
	return fixed
}

func sameName(ecosystem, a, b string) bool {
	if ecosystem == libraries.PyPI {
		return strings.EqualFold(strings.NewReplacer("_", "-", ".", "-").Replace(a), strings.NewReplacer("_", "-", ".", "-").Replace(b))
	}
	return a == b
}

func title(library libraries.Library, record Vulnerability) string {
	summary := strings.TrimSpace(record.Summary)
	if summary == "" {
		// Some sources, such as PyPA's, have only details: use their first line.
		summary, _, _ = strings.Cut(strings.TrimSpace(record.Details), "\n")
		summary = strings.TrimSpace(summary)
	}
	if summary == "" {
		summary = record.ID
	}
	if len(summary) > 160 {
		summary = summary[:160] + "…"
	}
	return fmt.Sprintf("%s %s (%s): %s", library.Name, library.Version, library.Ecosystem, summary)
}

func detail(cve, id string, fixed []string, exploit *advisory.Exploit) string {
	var parts []string
	if cve != "" && cve != id {
		parts = append(parts, cve+".")
	}
	switch len(fixed) {
	case 0:
		parts = append(parts, "No fixed version published yet.")
	default:
		parts = append(parts, "Fixed in "+strings.Join(fixed, ", ")+".")
	}
	if exploit != nil && exploit.KEV {
		parts = append(parts, "Known to be exploited (CISA KEV).")
	} else if exploit != nil && exploit.EPSS != nil && *exploit.EPSS >= advisory.LikelyEPSS {
		parts = append(parts, fmt.Sprintf("Likely to be exploited (EPSS %.0f%%).", *exploit.EPSS*100))
	}
	parts = append(parts, "https://osv.dev/vulnerability/"+id)
	return strings.Join(parts, " ")
}

func evidence(paths []string) string {
	if len(paths) <= 5 {
		return strings.Join(paths, "\n")
	}
	return strings.Join(paths[:5], "\n") + fmt.Sprintf("\nand %d more files", len(paths)-5)
}
