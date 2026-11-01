package compliance

import (
	"strings"
	"testing"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
)

func TestSTIGFollowsTheControls(t *testing.T) {
	control := func(id, status string) audit.Control {
		return audit.Control{ControlResult: checks.ControlResult{ID: id, Status: status}, STIG: checks.STIGRules("Red Hat Enterprise Linux 9.4", id)}
	}
	summary := audit.Summary{Controls: []audit.Control{
		control("KRN-01", checks.ControlPass), // same setting: met
		control("KRN-07", checks.ControlPass), // the STIG asks for more: partly checked
		control("SSH-04", checks.ControlFail), // not met
	}}
	framework, _ := Find(STIG)
	result := Evaluate(summary, framework)
	if result.Framework.Name != "DISA RHEL 9 STIG V2R10, 30 September 2026" || result.Met != 1 || result.NotMet != 1 || result.Other != 2 {
		t.Fatalf("result: %s, %d met, %d not met, %d other", result.Framework.Name, result.Met, result.NotMet, result.Other)
	}
	got := map[string]string{}
	for _, requirement := range result.Requirements {
		got[requirement.ID] = requirement.Status
		if requirement.Name == "" {
			t.Errorf("%s has no title", requirement.ID)
		}
	}
	if got["V-257809"] != Met || got["V-257813"] != Partial || got["V-257814"] != Partial || got["V-258007"] != NotMet {
		t.Errorf("statuses: %v", got)
	}
	if empty := Evaluate(audit.Summary{Controls: []audit.Control{{ControlResult: checks.ControlResult{ID: "KRN-01", Status: checks.ControlPass}}}}, framework); len(empty.Requirements) != 0 ||
		!strings.Contains(empty.Note, "has none of them") {
		t.Errorf("no STIG: %+v", empty)
	}
}
