package policy

import (
	"strings"
	"testing"

	"deaconguard/internal/checks"
)

func TestExampleParsesAndEvaluates(t *testing.T) {
	parsed, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	facts := &checks.Facts{
		SSHD:      map[string]string{"permitrootlogin": "prohibit-password"},
		LoginDefs: map[string]string{"pass_max_days": "60"},
		Packages:  []string{"openssh-server"},
		Active:    []string{"node_exporter"},
	}
	listening := []checks.Listening{{Protocol: "tcp", Address: "0.0.0.0", Port: 3306, Exposed: true}}
	results := Evaluate(parsed, facts, listening)
	want := map[string]string{"ACME-01": "fail", "ACME-02": "pass", "ACME-03": "pass", "ACME-04": "pass", "ACME-05": "fail"}
	for _, result := range results {
		if result.Status != want[result.ID] {
			t.Errorf("%s = %s (%s), want %s", result.ID, result.Status, result.Evidence, want[result.ID])
		}
		if result.Category != "Acme server policy" {
			t.Errorf("%s category = %q", result.ID, result.Category)
		}
	}
	if old := Evaluate(parsed, nil, nil); old[0].Status != checks.ControlUnknown {
		t.Fatalf("without facts = %s", old[0].Status)
	}
}

func TestBadPoliciesSayWhatIsWrong(t *testing.T) {
	cases := map[string]string{
		"name: x\ncontrols: []":             "1 to 200 controls",
		"name: x\nunknown: 1\ncontrols: []": "field unknown not found",
		"name: x\ncontrols:\n  - {id: SSH-01, title: t, severity: low, check: {package: {name: a}}}":                 "baseline control",
		"name: x\ncontrols:\n  - {id: A-1, title: t, severity: urgent, check: {package: {name: a}}}":                 "severity",
		"name: x\ncontrols:\n  - {id: A-1, title: t, severity: low, check: {}}":                                      "exactly one",
		"name: x\ncontrols:\n  - {id: A-1, title: t, severity: low, check: {file: {path: /etc/hosts, owner: r}}}":    "only the files",
		"name: x\ncontrols:\n  - {id: A-1, title: t, severity: low, check: {sshd: {setting: a}}}":                    "is, at_most or at_least",
		"name: x\ncontrols:\n  - {id: A-1, title: t, severity: low, check: {port: {port: 99999, listening: false}}}": "1 to 65535",
	}
	for source, message := range cases {
		if _, err := Parse([]byte(source)); err == nil || !strings.Contains(err.Error(), message) {
			t.Errorf("%q: %v, want %q", source, err, message)
		}
	}
}
