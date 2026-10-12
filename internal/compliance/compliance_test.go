package compliance

import (
	"testing"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
	"deaconguard/internal/store"
)

func TestEveryControlAndRequirementIsMapped(t *testing.T) {
	for _, id := range checks.BaselineIDs() {
		if _, mapped := mapping[id]; !mapped {
			t.Errorf("control %s has no mapping", id)
		}
	}
	for id, references := range mapping {
		for frameworkID, requirements := range references {
			framework, found := Find(frameworkID)
			if !found {
				t.Fatalf("%s maps to unknown framework %s", id, frameworkID)
			}
			for _, requirement := range requirements {
				if framework.Requirements[requirement] == "" {
					t.Errorf("%s maps to %s %s, which has no name", id, framework.Short, requirement)
				}
			}
		}
	}
}

func TestRequirementsTakeTheWorstOfTheirControls(t *testing.T) {
	summary := audit.Summary{
		Controls: []audit.Control{
			{ControlResult: checks.ControlResult{ID: "ACC-05", Status: checks.ControlPass}},
			{ControlResult: checks.ControlResult{ID: "ACC-11", Status: checks.ControlFail}}, // 8.3.4 with ACC-05 and SSH-05
			{ControlResult: checks.ControlResult{ID: "SSH-05", Status: audit.Accepted}},
			{ControlResult: checks.ControlResult{ID: "ACC-04", Status: audit.Accepted}},      // 8.3.6 alone
			{ControlResult: checks.ControlResult{ID: "TIME-01", Status: checks.ControlPass}}, // 10.6.1
			{ControlResult: checks.ControlResult{ID: "TIME-02", Status: checks.ControlUnknown}},
		},
		Packages: &store.FixSummary{Actionable: store.SeverityCounts{High: 1}},
		Checks:   []audit.Check{{ID: checks.Antivirus, Status: checks.StatusCompleted}},
	}
	framework, _ := Find(PCI)
	result := Evaluate(summary, framework)
	statuses := map[string]string{}
	for _, requirement := range result.Requirements {
		statuses[requirement.ID] = requirement.Status
	}
	want := map[string]string{"8.3.4": NotMet, "8.3.6": MetAccepted, "10.6.1": NotChecked, "6.3.3": NotMet, "5.2.1": Met, "5.3.2": Met}
	for id, status := range want {
		if statuses[id] != status {
			t.Errorf("%s = %s, want %s", id, statuses[id], status)
		}
	}
	if result.Requirements[0].ID != "5.2.1" {
		t.Errorf("requirements are not in order: %s first", result.Requirements[0].ID)
	}
	if !naturalLess("8.3.4", "8.3.10") || !naturalLess("AC-7", "AC-12") || naturalLess("10.2.1", "2.2.6") {
		t.Error("natural order is wrong")
	}
}
