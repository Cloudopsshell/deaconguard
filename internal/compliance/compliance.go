// Package compliance maps the DeaconGuard Linux baseline, and the checks for
// vulnerabilities, file integrity and malware, to requirements of common
// security frameworks, so an audit can be read framework by framework.
//
// The mapping is DeaconGuard's own, for guidance: it says which of a
// framework's requirements a host audit gives evidence for. Frameworks also
// ask for policies, people and processes no scan can see, so a fully met
// mapping is not a certification. Requirements are referenced by number;
// their names here are short descriptions, not the frameworks' text.
package compliance

import (
	"sort"
	"strings"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
)

// Framework is a security standard requirements are mapped to.
type Framework struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Short is the name used in tabs and reports.
	Short string `json:"short"`
	// Requirements name each requirement the mapping uses, by number.
	Requirements map[string]string `json:"-"`
}

// Status of a requirement on a host.
const (
	Met          = "met"           // every mapped control passed
	MetAccepted  = "met_accepted"  // met, with accepted risks
	NotMet       = "not_met"       // a mapped control failed
	NotChecked   = "not_checked"   // nothing mapped could be checked
	NotEvaluated = "not_evaluated" // no mapped control applies to this host
	// Partial is a STIG rule whose controls passed, but which asks for more
	// than they check, so it needs checking by hand.
	Partial = "partial"
)

// Requirement is one framework requirement and what the audit found for it.
type Requirement struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Status   string     `json:"status"`
	Controls []Evidence `json:"controls"`
}

// Evidence is one control or check behind a requirement.
type Evidence struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// Result is a framework's view of one audit.
type Result struct {
	Framework    Framework     `json:"framework"`
	Requirements []Requirement `json:"requirements"`
	Met          int           `json:"met"`
	NotMet       int           `json:"not_met"`
	Other        int           `json:"other"`
	// Note explains an empty result, such as a machine with no STIG.
	Note string `json:"note,omitempty"`
}

// Frameworks lists the frameworks in display order.
func Frameworks() []Framework { return frameworks }

// Find returns a framework by ID.
func Find(id string) (Framework, bool) {
	for _, framework := range frameworks {
		if framework.ID == id {
			return framework, true
		}
	}
	return Framework{}, false
}

// Evaluate reads an audit framework by framework.
func Evaluate(summary audit.Summary, framework Framework) Result {
	if framework.ID == STIG {
		return evaluateSTIG(summary, framework)
	}
	evidence := map[string]Evidence{}
	for _, control := range summary.Controls {
		evidence[control.ID] = Evidence{ID: control.ID, Title: control.Title, Status: control.Status}
	}
	// The other checks count as evidence too: vulnerabilities, file
	// integrity, malware indicators and the antivirus scan.
	if summary.Packages != nil {
		status := checks.ControlPass
		if summary.Packages.Actionable.Critical+summary.Packages.Actionable.High > 0 {
			status = checks.ControlFail
		}
		evidence["CHECK-packages"] = Evidence{ID: "CHECK-packages", Title: "No critical or high vulnerability has a fix waiting to be installed", Status: status}
	}
	for _, check := range summary.Checks {
		id := "CHECK-" + check.ID
		if _, mapped := checkTitles[id]; !mapped {
			continue
		}
		status := checks.ControlPass
		switch {
		case check.Status == checks.StatusFailed || check.Status == checks.StatusSkipped || check.Status == "":
			status = checks.ControlUnknown
		case check.Findings > 0:
			status = checks.ControlFail
		}
		evidence[id] = Evidence{ID: id, Title: checkTitles[id], Status: status}
	}

	byRequirement := map[string][]Evidence{}
	for controlID, mapped := range mapping {
		item, found := evidence[controlID]
		if !found {
			continue
		}
		for _, requirement := range mapped[framework.ID] {
			byRequirement[requirement] = append(byRequirement[requirement], item)
		}
	}
	result := Result{Framework: framework, Requirements: []Requirement{}}
	for id, items := range byRequirement {
		sort.Slice(items, func(a, b int) bool { return items[a].ID < items[b].ID })
		requirement := Requirement{ID: id, Name: framework.Requirements[id], Controls: items, Status: status(items)}
		switch requirement.Status {
		case Met, MetAccepted:
			result.Met++
		case NotMet:
			result.NotMet++
		default:
			result.Other++
		}
		result.Requirements = append(result.Requirements, requirement)
	}
	sort.Slice(result.Requirements, func(a, b int) bool {
		return naturalLess(result.Requirements[a].ID, result.Requirements[b].ID)
	})
	return result
}

// evaluateSTIG reads an audit rule by rule of the DISA STIG for the
// machine's operating system, from the rules each control checks.
func evaluateSTIG(summary audit.Summary, framework Framework) Result {
	result := Result{Framework: framework, Requirements: []Requirement{}}
	byRule := map[string][]Evidence{}
	stricter := map[string]bool{}
	for _, control := range summary.Controls {
		for _, rule := range control.STIG {
			if len(byRule[rule.Rule]) == 0 {
				result.Framework.Name = rule.STIG
			}
			byRule[rule.Rule] = append(byRule[rule.Rule], Evidence{ID: control.ID, Title: control.Title, Status: control.Status})
			stricter[rule.Rule] = stricter[rule.Rule] || rule.Note != ""
		}
	}
	if len(byRule) == 0 {
		result.Note = "DeaconGuard maps its baseline to the DISA STIGs for Ubuntu 22.04 and 24.04 and for RHEL 8 and 9, also used for Rocky Linux and AlmaLinux. This machine's operating system has none of them."
		return result
	}
	for _, guide := range checks.STIGGuides() {
		if guide.Name == result.Framework.Name {
			result.Framework.Name += " " + guide.Release
		}
	}
	for id, items := range byRule {
		sort.Slice(items, func(a, b int) bool { return items[a].ID < items[b].ID })
		requirement := Requirement{ID: id, Name: checks.STIGTitle(id), Controls: items, Status: status(items)}
		if stricter[id] && (requirement.Status == Met || requirement.Status == MetAccepted) {
			requirement.Status = Partial
		}
		switch requirement.Status {
		case Met, MetAccepted:
			result.Met++
		case NotMet:
			result.NotMet++
		default:
			result.Other++
		}
		result.Requirements = append(result.Requirements, requirement)
	}
	sort.Slice(result.Requirements, func(a, b int) bool { return result.Requirements[a].ID < result.Requirements[b].ID })
	return result
}

func status(items []Evidence) string {
	failed, accepted, passed, unknown := false, false, false, false
	for _, item := range items {
		switch item.Status {
		case checks.ControlFail:
			failed = true
		case audit.Accepted:
			accepted = true
		case checks.ControlPass:
			passed = true
		case checks.ControlUnknown:
			unknown = true
		}
	}
	switch {
	case failed:
		return NotMet
	case unknown:
		return NotChecked
	case accepted:
		return MetAccepted
	case passed:
		return Met
	}
	return NotEvaluated
}

// naturalLess orders requirement numbers such as 8.3.4 before 8.3.10, and
// AC-7 before AC-12.
func naturalLess(a, b string) bool {
	split := func(value string) []string {
		return strings.FieldsFunc(value, func(r rune) bool { return r == '.' || r == '-' || r == '(' || r == ')' || r == ' ' })
	}
	left, right := split(a), split(b)
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] == right[index] {
			continue
		}
		leftNumber, leftIsNumber := number(left[index])
		rightNumber, rightIsNumber := number(right[index])
		if leftIsNumber && rightIsNumber {
			return leftNumber < rightNumber
		}
		return left[index] < right[index]
	}
	return len(left) < len(right)
}

func number(value string) (int, bool) {
	result := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		result = result*10 + int(r-'0')
	}
	return result, value != ""
}
