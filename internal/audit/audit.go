// Package audit grades a handover audit: one scan that ran every check,
// including the hardening baseline. The grade starts from the share of
// baseline controls that pass, weighted by severity, and is then capped by
// anything that should stop a handover: malware, changed system files,
// fixable critical or high vulnerabilities, and failed critical controls.
package audit

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/store"
)

// Accepted is a control that failed but whose risk an admin accepted.
const Accepted = "accepted"

// Control is a baseline control's result, with its accepted risk if any.
type Control struct {
	checks.ControlResult
	Exception *store.Exception `json:"exception,omitempty"`
}

type Counts struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Accepted      int `json:"accepted"`
	NotApplicable int `json:"not_applicable"`
	Unknown       int `json:"unknown"`
}

type Category struct {
	Name string `json:"name"`
	Counts
}

// Check summarises one of the audit's other checks.
type Check struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Summary    string `json:"summary"`
	Findings   int    `json:"findings"`
	Privileged bool   `json:"privileged"`
}

// Summary is everything the audit page and reports show.
type Summary struct {
	Grade string `json:"grade"`
	Score int    `json:"score"`
	// Caps explains each reason the grade is lower than the score alone.
	Caps []string `json:"caps"`
	// Incomplete lists what could not be checked fully; the grade then
	// covers only what was.
	Incomplete []string             `json:"incomplete"`
	Counts     Counts               `json:"counts"`
	Categories []Category           `json:"categories"`
	Controls   []Control            `json:"controls"`
	Inventory  *checks.Inventory    `json:"inventory"`
	Checks     []Check              `json:"checks"`
	Packages   *store.FixSummary    `json:"packages"`
	Severity   store.SeverityCounts `json:"severity"`
}

// Checks every audit runs. The advanced antivirus scan is optional.
var Checks = []string{checks.Packages, checks.Integrity, checks.Malware, checks.Config, checks.Hardening, checks.Antivirus}

var weights = map[string]float64{"critical": 10, "high": 6, "medium": 3, "low": 1}

var grades = []string{"A", "B", "C", "D", "F"}

func gradeFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}

// cap lowers grade to at most limit, recording why.
func (s *Summary) cap(limit, reason string) {
	current, wanted := 0, 0
	for index, grade := range grades {
		if grade == s.Grade {
			current = index
		}
		if grade == limit {
			wanted = index
		}
	}
	if wanted > current {
		s.Grade = limit
	}
	s.Caps = append(s.Caps, fmt.Sprintf("%s (at most %s)", reason, limit))
}

// Grade summarises an audit from its scan and report, applying the risks
// accepted for its host at now.
func Grade(scan store.Scan, report map[string]any, exceptions []store.Exception, now time.Time) (Summary, error) {
	summary := Summary{Caps: []string{}, Incomplete: []string{}, Controls: []Control{}, Checks: []Check{}, Packages: scan.Fixes, Severity: scan.Severity}
	results := map[string]checks.Result{}
	if raw, ok := report["check_results"]; ok {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return summary, err
		}
		if err := json.Unmarshal(encoded, &results); err != nil {
			return summary, fmt.Errorf("read the check results: %w", err)
		}
	}
	accepted := map[string]store.Exception{}
	for _, exception := range exceptions {
		if exception.Active(now) && (exception.HostID == "" || exception.HostID == scan.HostID) {
			if _, have := accepted[exception.ControlID]; !have || exception.HostID != "" {
				accepted[exception.ControlID] = exception
			}
		}
	}

	hardening, ran := results[checks.Hardening]
	if !ran || hardening.Status == checks.StatusFailed {
		summary.Incomplete = append(summary.Incomplete, "The hardening baseline did not run.")
	}
	summary.Inventory = hardening.Inventory
	categories := map[string]*Category{}
	for _, name := range checks.Categories() {
		categories[name] = &Category{Name: name}
	}
	var passedWeight, failedWeight float64
	criticalFailed := 0
	for _, result := range hardening.Controls {
		control := Control{ControlResult: result}
		category := categories[result.Category]
		if category == nil {
			category = &Category{Name: result.Category}
			categories[result.Category] = category
		}
		switch result.Status {
		case checks.ControlPass:
			summary.Counts.Passed++
			category.Passed++
			passedWeight += weights[result.Severity]
		case checks.ControlFail:
			if exception, ok := accepted[result.ID]; ok {
				control.Status, control.Exception = Accepted, &exception
				summary.Counts.Accepted++
				category.Accepted++
				break
			}
			summary.Counts.Failed++
			category.Failed++
			failedWeight += weights[result.Severity]
			if result.Severity == "critical" {
				criticalFailed++
			}
		case checks.ControlNA:
			summary.Counts.NotApplicable++
			category.NotApplicable++
		default:
			summary.Counts.Unknown++
			category.Unknown++
		}
		summary.Controls = append(summary.Controls, control)
	}
	for _, name := range checks.Categories() {
		summary.Categories = append(summary.Categories, *categories[name])
	}
	if passedWeight+failedWeight > 0 {
		summary.Score = int(math.Round(100 * passedWeight / (passedWeight + failedWeight)))
	}
	summary.Grade = gradeFor(summary.Score)
	if summary.Counts.Unknown > 0 {
		summary.Incomplete = append(summary.Incomplete, fmt.Sprintf("%d controls could not be checked, usually because the audit ran without root.", summary.Counts.Unknown))
	}

	names := map[string]string{}
	for _, definition := range checks.Definitions() {
		names[definition.ID] = definition.Name
	}
	for _, id := range scan.Checks {
		if id == checks.Packages || id == checks.Hardening {
			continue
		}
		result := results[id]
		summary.Checks = append(summary.Checks, Check{ID: id, Name: names[id], Status: result.Status, Summary: result.Summary,
			Findings: len(result.Findings), Privileged: result.Privileged})
		if result.Status == checks.StatusFailed || result.Status == checks.StatusSkipped || result.Status == "" {
			summary.Incomplete = append(summary.Incomplete, fmt.Sprintf("%s did not run: %s", names[id], firstOf(result.Error, result.Summary, "no result")))
		}
	}
	if !contains(scan.Checks, checks.Packages) || scan.Fixes == nil {
		summary.Incomplete = append(summary.Incomplete, "Package vulnerabilities were not checked.")
	}

	// What should stop a handover lowers the grade, whatever the score.
	if found := len(results[checks.Malware].Findings) + len(results[checks.Antivirus].Findings) + len(results[checks.YARA].Findings); found > 0 {
		summary.cap("F", fmt.Sprintf("Malware or signs of compromise were found (%d)", found))
	}
	if changed := severe(results[checks.Integrity]); changed > 0 {
		summary.cap("D", fmt.Sprintf("%d system files differ from what their packages installed", changed))
	}
	if scan.Fixes != nil && scan.Fixes.Actionable.Critical > 0 {
		summary.cap("C", fmt.Sprintf("%d critical vulnerabilities have a fix available", scan.Fixes.Actionable.Critical))
	}
	if criticalFailed > 0 {
		summary.cap("C", fmt.Sprintf("%d critical baseline controls failed", criticalFailed))
	}
	if scan.Fixes != nil && scan.Fixes.Actionable.High > 0 {
		summary.cap("B", fmt.Sprintf("%d high-severity vulnerabilities have a fix available", scan.Fixes.Actionable.High))
	}
	return summary, nil
}

// severe counts critical and high findings.
func severe(result checks.Result) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
			count++
		}
	}
	return count
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func firstOf(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
