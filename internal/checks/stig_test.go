package checks

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestSTIGMappingIsWellFormed(t *testing.T) {
	ids := BaselineIDs()
	guides := map[string]bool{}
	for _, guide := range STIGGuides() {
		guides[guide.Key] = true
	}
	ruleID := regexp.MustCompile(`^V-\d{6}$`)
	for control, byGuide := range baselineSTIG {
		if !slices.Contains(ids, control) {
			t.Errorf("%s isn't a baseline control", control)
		}
		for guide, rules := range byGuide {
			if !guides[guide] {
				t.Errorf("%s: unknown STIG %s", control, guide)
			}
			seen := map[string]bool{}
			for _, rule := range rules {
				if !ruleID.MatchString(rule.rule) || seen[rule.rule] {
					t.Errorf("%s %s: bad or repeated rule %q", control, guide, rule.rule)
				}
				seen[rule.rule] = true
				if STIGTitle(rule.rule) == "" {
					t.Errorf("%s %s: %s has no title", control, guide, rule.rule)
				}
			}
		}
	}
}

func TestSTIGForOperatingSystems(t *testing.T) {
	for os, want := range map[string]string{
		"Ubuntu 22.04 LTS": "ubuntu-22.04", "Ubuntu 24.04 LTS": "ubuntu-24.04", "Red Hat Enterprise Linux 8.10": "rhel-8",
		"Red Hat Enterprise Linux 9.6": "rhel-9", "Rocky Linux 9.3": "rhel-9", "AlmaLinux 8.9": "rhel-8", "AlmaLinux 9": "rhel-9",
		"Ubuntu 20.04 LTS": "", "Debian 12 (bookworm)": "", "Oracle Linux 9.4": "", "AlmaLinux 10.0": "", "Rocky Linux 89": "", "macOS 15.5": "",
	} {
		guide, ok := STIGFor(os)
		if ok != (want != "") || guide.Key != want {
			t.Errorf("STIGFor(%q) = %q, %v; want %q", os, guide.Key, ok, want)
		}
	}
	rules := STIGRules("Rocky Linux 9.3", "KRN-07")
	if len(rules) != 2 || rules[0].STIG != "DISA RHEL 9 STIG" || rules[0].Rule != "V-257813" || rules[0].Note == "" {
		t.Errorf("KRN-07 on Rocky Linux 9: %+v", rules)
	}
	if rules := STIGRules("Ubuntu 24.04 LTS", "KRN-01"); len(rules) != 1 || rules[0].Rule != "V-270772" || rules[0].Note != "" {
		t.Errorf("KRN-01 on Ubuntu 24.04: %+v", rules)
	}
	if rules := STIGRules("Debian 12 (bookworm)", "KRN-01"); rules != nil {
		t.Errorf("Debian has no STIG: %+v", rules)
	}
	if rules, controls := STIGControls(stigRHEL9); len(rules) == 0 || !slices.Equal(controls["V-270690"], nil) || !slices.Equal(controls["V-258054"], []string{"ACC-05", "ACC-11"}) {
		t.Errorf("RHEL 9: %d rules, V-258054 checked by %v", len(rules), controls["V-258054"])
	}
}

// TestWriteSTIGDocs writes the STIG mapping as a Markdown table for the docs:
// DEACONGUARD_STIG_DOCS=file go test ./internal/checks -run WriteSTIGDocs
func TestWriteSTIGDocs(t *testing.T) {
	path := os.Getenv("DEACONGUARD_STIG_DOCS")
	if path == "" {
		t.Skip("set DEACONGUARD_STIG_DOCS to write the table")
	}
	guides := STIGGuides()
	var builder strings.Builder
	builder.WriteString("| Control |")
	for _, guide := range guides {
		builder.WriteString(" " + strings.TrimSuffix(strings.TrimPrefix(guide.Name, "DISA "), " STIG") + " |")
	}
	builder.WriteString(" The STIG asks for more |\n| --- |" + strings.Repeat(" --- |", len(guides)+1) + "\n")
	for _, control := range BaselineIDs() {
		if baselineSTIG[control] == nil {
			continue
		}
		fmt.Fprintf(&builder, "| %s |", control)
		note := ""
		for _, guide := range guides {
			var ids []string
			for _, rule := range baselineSTIG[control][guide.Key] {
				ids = append(ids, rule.rule)
				if rule.note != "" && !strings.Contains(note, rule.note) {
					note = strings.TrimSpace(note + " " + rule.note)
				}
			}
			fmt.Fprintf(&builder, " %s |", strings.Join(ids, ", "))
		}
		fmt.Fprintf(&builder, " %s |\n", strings.ReplaceAll(note, "|", "\\|"))
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
