package report

import (
	"fmt"
	"strings"

	"deaconguard/internal/checks"
	"deaconguard/internal/compliance"
)

// STIGIDs lists a control's STIG rules, such as "DISA RHEL 9 STIG V-230313,
// V-230314", for tables.
func STIGIDs(rules []checks.STIGRule) string {
	var guides []string
	ids := map[string][]string{}
	for _, rule := range rules {
		if len(ids[rule.STIG]) == 0 {
			guides = append(guides, rule.STIG)
		}
		ids[rule.STIG] = append(ids[rule.STIG], rule.Rule)
	}
	var parts []string
	for _, guide := range guides {
		parts = append(parts, guide+" "+strings.Join(ids[guide], ", "))
	}
	return strings.Join(parts, "; ")
}

// STIGText is STIGIDs with what the STIG asks for beyond the control, for
// a control's details.
func STIGText(rules []checks.STIGRule) string {
	text := STIGIDs(rules)
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Note != "" && !seen[rule.Note] {
			seen[rule.Note] = true
			text += ". " + strings.TrimSuffix(rule.Note, ".")
		}
	}
	if text != "" && len(seen) > 0 {
		text += "."
	}
	return text
}

// ComplianceIntro introduces a framework's part of a report.
func ComplianceIntro(result compliance.Result) string {
	if result.Framework.ID == compliance.STIG {
		if result.Note != "" {
			return result.Note
		}
		return fmt.Sprintf("The rules of this STIG that a baseline control checks: %d met, %d not met, %d partly or not checked. "+
			"Partly checked: the control passed, but the rule asks for more, so check the rest by hand. This is DeaconGuard's mapping, for guidance; "+
			"a STIG assessment covers many rules DeaconGuard doesn't read, so this is not one.", result.Met, result.NotMet, result.Other)
	}
	other := ""
	if result.Other > 0 {
		other = fmt.Sprintf(", %d not checked", result.Other)
	}
	return fmt.Sprintf("The requirements this audit gives evidence for: %d met, %d not met%s. This is DeaconGuard's mapping, for guidance. "+
		"The framework also has requirements about policies, people and processes that no scan can check, so this is not a certification.",
		result.Met, result.NotMet, other)
}
