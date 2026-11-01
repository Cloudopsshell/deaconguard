package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"deaconguard/internal/checks"
)

// SharedKeyHosts is how many hosts must trust the same SSH key before the
// attack path check reports it: one stolen key then opens all of them.
const SharedKeyHosts = 3

// KeyHost is another host that trusts a key, and as which account.
type KeyHost struct {
	Host    string
	Account string
	Root    bool
}

// KeyFingerprint is the fingerprint in an SSH key's snapshot item, whose
// key is "account fingerprint".
func KeyFingerprint(item checks.SnapshotItem) (account, fingerprint string) {
	account, fingerprint, _ = strings.Cut(item.Key, " ")
	return account, fingerprint
}

// EvaluateSharedKeys adds a finding to the attack path check's result, in
// place in the report, for each SSH key this host trusts that at least
// SharedKeyHosts hosts trust in all. others lists, by fingerprint, the
// other hosts that trust it.
func EvaluateSharedKeys(report map[string]any, others map[string][]KeyHost) error {
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
	result, ok := results[checks.Paths]
	if !ok || result.Status == checks.StatusFailed || result.Status == checks.StatusSkipped {
		return nil
	}
	findings := SharedKeyFindings(result.Keys, others)
	if len(findings) == 0 {
		return nil
	}
	result.Findings = append(result.Findings, findings...)
	sort.SliceStable(result.Findings, func(i, j int) bool {
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	result.Summary += "; " + plural(len(findings), "SSH key", "SSH keys") + " trusted on many machines"
	results[checks.Paths] = result
	report["check_results"] = results
	return nil
}

// SharedKeyFindings reports the keys of keys, this host's, that enough
// other hosts trust too.
func SharedKeyFindings(keys []checks.SnapshotItem, others map[string][]KeyHost) []checks.Finding {
	type here struct {
		accounts []string
		root     bool
		text     string
	}
	var order []string
	local := map[string]*here{}
	for _, item := range keys {
		account, fingerprint := KeyFingerprint(item)
		if fingerprint == "" {
			continue
		}
		key := local[fingerprint]
		if key == nil {
			key = &here{text: item.Text}
			local[fingerprint] = key
			order = append(order, fingerprint)
		}
		key.accounts = append(key.accounts, account)
		key.root = key.root || item.Root
	}
	var findings []checks.Finding
	for _, fingerprint := range order {
		key := local[fingerprint]
		hosts := map[string]bool{}
		root := key.root
		var where []string
		for _, other := range others[fingerprint] {
			if !hosts[other.Host] {
				hosts[other.Host] = true
				where = append(where, other.Host+" ("+other.Account+")")
			}
			root = root || other.Root
		}
		if len(hosts)+1 < SharedKeyHosts {
			continue
		}
		severity := "MEDIUM"
		if root {
			severity = "HIGH"
		}
		shown := where
		if len(shown) > 5 {
			shown = append(shown[:5:5], fmt.Sprintf("%d more", len(where)-5))
		}
		// The item's text ends "SHA256:… (ops@laptop)" when the key has a comment.
		label := fingerprint
		if _, comment, found := strings.Cut(key.text, fingerprint+" ("); found {
			label += " (" + comment
		}
		as := strings.Join(key.accounts, ", ")
		findings = append(findings, checks.Finding{Rule: checks.RuleSharedKey, Severity: severity,
			Title: fmt.Sprintf("The SSH key %s is trusted on %d machines", label, len(hosts)+1),
			Detail: fmt.Sprintf("The same key logs in here as %s, and on %s. Whoever gets it, from a laptop, a CI secret or a backup, reaches all of them at once. "+
				"Give each machine or team its own key, and remove this one where it isn't needed.", as, strings.Join(shown, ", ")),
			Evidence: "here (" + as + "), " + strings.Join(shown, ", "),
			Path:     []string{"whoever has the key", "logs in here as " + as, fmt.Sprintf("and on %s", plural(len(hosts), "other machine", "other machines"))}})
	}
	return findings
}
