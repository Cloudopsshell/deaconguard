package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"deaconguard/internal/checks"
)

// MaxChangeFindings is the most changes one scan reports; an upgrade that
// enables many services or a new image of the machine would otherwise fill
// the page.
const MaxChangeFindings = 100

// change is how a section's additions and removals are reported.
type change struct {
	rule, added, removed string
	severity             func(item checks.SnapshotItem) string
	advice               string
}

var changeKinds = map[string]change{
	checks.SectionListening: {rule: "DG-CHG-001", added: "New listening port", removed: "Port no longer listening",
		severity: func(item checks.SnapshotItem) string {
			if item.Exposed {
				return "HIGH"
			}
			return "LOW"
		}, advice: "If you didn't start this service, find it with ss -tulnp and stop it; otherwise close the port in the firewall if it shouldn't be reachable."},
	checks.SectionUsers: {rule: "DG-CHG-002", added: "New login account", removed: "Login account removed",
		severity: func(item checks.SnapshotItem) string {
			if strings.HasSuffix(item.Key, " uid 0") {
				return "CRITICAL"
			}
			return "MEDIUM"
		}, advice: "If nobody on your team added it, lock it (usermod -L) and look at how it was created: an account with UID 0 is a second root."},
	checks.SectionAdmins: {rule: "DG-CHG-003", added: "New administrator", removed: "Administrator removed",
		severity: constant("HIGH"), advice: "If nobody on your team gave these rights, remove the account from the group and look at its recent logins."},
	checks.SectionSudoers: {rule: "DG-CHG-004", added: "New sudoers rule", removed: "Sudoers rule removed",
		severity: constant("HIGH"), advice: "If nobody on your team added it, remove it with visudo: sudoers rules give root."},
	// A key for root, or another account with UID 0, logs in as root.
	checks.SectionKeys: {rule: "DG-CHG-005", added: "New SSH key", removed: "SSH key removed",
		severity: func(item checks.SnapshotItem) string {
			if item.Root {
				return "HIGH"
			}
			return "MEDIUM"
		}, advice: "If nobody on your team added it, remove the line from the account's authorized_keys: whoever has the key can log in."},
	checks.SectionServices: {rule: "DG-CHG-006", added: "New enabled service", removed: "Service no longer enabled",
		severity: constant("MEDIUM"), advice: "If you didn't install or enable it, look at what it runs (systemctl cat) and disable it."},
	checks.SectionCron: {rule: "DG-CHG-007", added: "New scheduled job", removed: "Scheduled job removed",
		severity: constant("MEDIUM"), advice: "If you didn't add it, look at what it runs and remove it: scheduled jobs are a common way to keep access."},
}

// changeOrder is the order changes are listed in, most telling first.
var changeOrder = []string{checks.SectionUsers, checks.SectionAdmins, checks.SectionSudoers, checks.SectionKeys,
	checks.SectionListening, checks.SectionCron, checks.SectionServices}

func constant(severity string) func(checks.SnapshotItem) string {
	return func(checks.SnapshotItem) string { return severity }
}

// EvaluateChanges compares the host change check's record with previous,
// the host's previous one (nil for none), and adds a finding for each
// change, in place in the report's check results. Removals are low: worth
// knowing, rarely an attack.
func EvaluateChanges(report map[string]any, previous *checks.Snapshot) error {
	raw, ok := report["check_results"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var results map[string]checks.Result
	if err := json.Unmarshal(encoded, &results); err != nil {
		return fmt.Errorf("read check results: %w", err)
	}
	result, ok := results[checks.Changes]
	if !ok || result.Snapshot == nil || result.Status == checks.StatusFailed || result.Status == checks.StatusSkipped {
		return nil
	}
	findings, notes := CompareSnapshots(previous, result.Snapshot)
	result.Findings = append(result.Findings, findings...)
	result.Notes = append(result.Notes, notes...)
	if previous != nil {
		result.Summary += "; " + plural(len(findings), "change", "changes") + " since the previous scan"
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	results[checks.Changes] = result
	report["check_results"] = results
	return nil
}

// CompareSnapshots lists what changed from previous to current. A section
// either record lacks, such as SSH keys in a scan without sudo, isn't
// compared.
func CompareSnapshots(previous, current *checks.Snapshot) ([]checks.Finding, []string) {
	if previous == nil {
		return nil, []string{"This is the first record of this machine: the next scans report what changes from it."}
	}
	var findings []checks.Finding
	var notes []string
	var skipped []string
	for _, section := range changeOrder {
		after, hasAfter := current.Sections[section]
		before, hasBefore := previous.Sections[section]
		if hasAfter != hasBefore {
			if hasAfter {
				skipped = append(skipped, checks.SectionName(section))
			}
			continue
		}
		if !hasAfter {
			continue
		}
		kind := changeKinds[section]
		was := map[string]bool{}
		for _, item := range before {
			was[item.Key] = true
		}
		is := map[string]bool{}
		for _, item := range after {
			is[item.Key] = true
			if !was[item.Key] {
				findings = append(findings, checks.Finding{Rule: kind.rule, Severity: kind.severity(item),
					Title: kind.added + ": " + item.Text, Detail: kind.added + " since the previous scan. " + kind.advice})
			}
		}
		for _, item := range before {
			if !is[item.Key] {
				findings = append(findings, checks.Finding{Rule: kind.rule, Severity: "LOW",
					Title: kind.removed + ": " + item.Text, Detail: kind.removed + " since the previous scan."})
			}
		}
	}
	if len(skipped) > 0 {
		notes = append(notes, "The previous scan ran without sudo, so these were recorded for the first time and will be compared from the next scan: "+strings.Join(skipped, ", ")+".")
	}
	if len(findings) > MaxChangeFindings {
		notes = append(notes, fmt.Sprintf("Only the first %d of the %d changes are listed.", MaxChangeFindings, len(findings)))
		findings = findings[:MaxChangeFindings]
	}
	return findings, notes
}
