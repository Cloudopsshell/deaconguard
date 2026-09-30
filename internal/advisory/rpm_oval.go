package advisory

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"deaconguard/internal/inventory"
	"deaconguard/internal/version"
)

const maxExpandedOVAL = 512 << 20

type ovalDocument struct {
	Definitions []ovalDefinition `xml:"definitions>definition"`
	Tests       []ovalTest       `xml:"tests>rpminfo_test"`
	Objects     []ovalObject     `xml:"objects>rpminfo_object"`
	States      []ovalState      `xml:"states>rpminfo_state"`
}

type ovalDefinition struct {
	ID       string       `xml:"id,attr"`
	Class    string       `xml:"class,attr"`
	Metadata ovalMetadata `xml:"metadata"`
	Criteria ovalCriteria `xml:"criteria"`
}

type ovalMetadata struct {
	Title       string          `xml:"title"`
	Description string          `xml:"description"`
	References  []ovalReference `xml:"reference"`
	Advisory    struct {
		Severity string `xml:"severity,attr"`
	} `xml:"advisory"`
}

type ovalReference struct {
	Source string `xml:"source,attr"`
	ID     string `xml:"ref_id,attr"`
	URL    string `xml:"ref_url,attr"`
}

type ovalCriteria struct {
	Operator  string          `xml:"operator,attr"`
	Negate    string          `xml:"negate,attr"`
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	TestRef string `xml:"test_ref,attr"`
	Negate  string `xml:"negate,attr"`
}

type ovalTest struct {
	ID             string  `xml:"id,attr"`
	Check          string  `xml:"check,attr"`
	CheckExistence string  `xml:"check_existence,attr"`
	Object         ovalRef `xml:"object"`
	State          ovalRef `xml:"state"`
}

type ovalRef struct {
	Ref      string `xml:"object_ref,attr"`
	StateRef string `xml:"state_ref,attr"`
}

type ovalObject struct {
	ID   string          `xml:"id,attr"`
	Name ovalObjectField `xml:"name"`
	Arch ovalObjectField `xml:"arch"`
}

type ovalObjectField struct {
	Value     string `xml:",chardata"`
	Operation string `xml:"operation,attr"`
	VarRef    string `xml:"var_ref,attr"`
}

type ovalState struct {
	ID  string  `xml:"id,attr"`
	EVR ovalEVR `xml:"evr"`
}

type ovalEVR struct {
	Value     string `xml:",chardata"`
	Operation string `xml:"operation,attr"`
	Datatype  string `xml:"datatype,attr"`
}

type ovalResult struct {
	state string
	items map[string]string
}

type rpmOVALEvaluator struct {
	document ovalDocument
	packages map[string][]inventory.Package
	tests    map[string]ovalResult
	objects  map[string]ovalObject
	states   map[string]ovalState
	testMap  map[string]ovalTest
}

func EvaluateRedHatOVAL(compressed []byte, packages []inventory.Package) (DebianEvaluation, error) {
	reader := io.LimitReader(bzip2.NewReader(bytes.NewReader(compressed)), maxExpandedOVAL+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return DebianEvaluation{}, fmt.Errorf("decompress Red Hat OVAL data: %w", err)
	}
	if len(data) == 0 || len(data) > maxExpandedOVAL {
		return DebianEvaluation{}, fmt.Errorf("Red Hat OVAL data is empty or exceeds %d bytes", maxExpandedOVAL)
	}
	return evaluateRedHatOVALXML(data, packages)
}

func evaluateRedHatOVALXML(data []byte, packages []inventory.Package) (DebianEvaluation, error) {
	var document ovalDocument
	if err := xml.Unmarshal(data, &document); err != nil {
		return DebianEvaluation{}, fmt.Errorf("parse Red Hat OVAL XML: %w", err)
	}
	if len(document.Definitions) == 0 {
		return DebianEvaluation{}, fmt.Errorf("Red Hat OVAL document contains no definitions")
	}
	evaluator := &rpmOVALEvaluator{
		document: document, packages: make(map[string][]inventory.Package), tests: make(map[string]ovalResult),
		objects: make(map[string]ovalObject), states: make(map[string]ovalState), testMap: make(map[string]ovalTest),
	}
	for _, item := range packages {
		evaluator.packages[item.Name] = append(evaluator.packages[item.Name], item)
	}
	for _, item := range document.Objects {
		evaluator.objects[item.ID] = item
	}
	for _, item := range document.States {
		evaluator.states[item.ID] = item
	}
	for _, item := range document.Tests {
		evaluator.testMap[item.ID] = item
	}

	result := DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}
	for _, definition := range document.Definitions {
		if definition.Class != "vulnerability" {
			continue
		}
		cves := make([]ovalReference, 0)
		for _, reference := range definition.Metadata.References {
			if strings.EqualFold(reference.Source, "CVE") || strings.HasPrefix(reference.ID, "CVE-") {
				cves = append(cves, reference)
			}
		}
		if len(cves) == 0 {
			continue
		}
		result.Evaluated++
		evaluation := evaluator.criteria(definition.Criteria, 0)
		if evaluation.state == "unknown" {
			for _, cve := range cves {
				result.Unsupported = append(result.Unsupported, Unsupported{
					ID: cve.ID, Title: definition.Metadata.Title,
					Reason: "OVAL rule contains checks not supported by the Go evaluator",
				})
			}
			continue
		}
		if evaluation.state != "true" {
			continue
		}
		itemNames := make([]string, 0, len(evaluation.items))
		for item := range evaluation.items {
			itemNames = append(itemNames, item)
		}
		sort.Strings(itemNames)
		for _, cve := range cves {
			for _, itemName := range itemNames {
				parts := strings.SplitN(itemName, "\x00", 2)
				packageName, installed := parts[0], "unknown"
				if len(parts) == 2 {
					installed = parts[1]
				}
				result.Findings = append(result.Findings, Finding{
					ID: cve.ID, Package: packageName, InstalledVersion: installed,
					FixedVersion: evaluation.items[itemName], Severity: normalizeSeverity(definition.Metadata.Advisory.Severity),
					URL: cve.URL, Title: definition.Metadata.Title,
				})
			}
		}
	}
	return result, nil
}

func (evaluator *rpmOVALEvaluator) criteria(criteria ovalCriteria, depth int) ovalResult {
	if depth > 20 {
		return ovalResult{state: "unknown"}
	}
	children := make([]ovalResult, 0, len(criteria.Criteria)+len(criteria.Criterion))
	for _, criterion := range criteria.Criterion {
		child := evaluator.test(criterion.TestRef)
		if criterion.Negate == "true" {
			child = negateOVAL(child)
		}
		children = append(children, child)
	}
	for _, nested := range criteria.Criteria {
		child := evaluator.criteria(nested, depth+1)
		if nested.Negate == "true" {
			child = negateOVAL(child)
		}
		children = append(children, child)
	}
	combined := combineOVAL(children, criteria.Operator)
	if criteria.Negate == "true" {
		return negateOVAL(combined)
	}
	return combined
}

func (evaluator *rpmOVALEvaluator) test(id string) ovalResult {
	if result, exists := evaluator.tests[id]; exists {
		return result
	}
	test, ok := evaluator.testMap[id]
	if !ok {
		return ovalResult{state: "unknown"}
	}
	object, objectOK := evaluator.objects[test.Object.Ref]
	if !objectOK || object.Name.Value == "" || object.Name.VarRef != "" {
		return ovalResult{state: "unknown"}
	}
	if object.Name.Operation != "" && object.Name.Operation != "equals" && object.Name.Operation != "pattern match" {
		return ovalResult{state: "unknown"}
	}
	nameMatcher := object.Name.Value
	if object.Name.Operation == "pattern match" {
		if _, err := regexp.Compile(nameMatcher); err != nil {
			return ovalResult{state: "unknown"}
		}
	}
	installed := make([]inventory.Package, 0)
	for packageName, packageItems := range evaluator.packages {
		matchesName := packageName == nameMatcher
		if object.Name.Operation == "pattern match" {
			matchesName, _ = regexp.MatchString(nameMatcher, packageName)
		}
		if !matchesName {
			continue
		}
		for _, packageItem := range packageItems {
			if object.Arch.Value != "" {
				if object.Arch.VarRef != "" || (object.Arch.Operation != "" && object.Arch.Operation != "equals") {
					return ovalResult{state: "unknown"}
				}
				if packageItem.Arch != object.Arch.Value {
					continue
				}
			}
			installed = append(installed, packageItem)
		}
	}
	checkExistence := test.CheckExistence
	if checkExistence == "" {
		checkExistence = "at_least_one_exists"
	}
	if len(installed) == 0 {
		if checkExistence == "none_exist" {
			return ovalResult{state: "true", items: map[string]string{}}
		}
		return ovalResult{state: "false"}
	}
	if checkExistence == "none_exist" {
		return ovalResult{state: "false"}
	}
	if checkExistence != "at_least_one_exists" && checkExistence != "all_exist" {
		return ovalResult{state: "unknown"}
	}
	state, hasState := evaluator.states[test.State.StateRef]
	items := make(map[string]string)
	matched := 0
	for _, installedPackage := range installed {
		if !hasState {
			matched++
			items[installedPackage.Name+"\x00"+installedPackage.Version] = ""
			continue
		}
		comparison, err := compareRPMEVR(installedPackage.Version, state.EVR.Value, state.EVR.Operation)
		if err != nil {
			return ovalResult{state: "unknown"}
		}
		if comparison {
			matched++
			items[installedPackage.Name+"\x00"+installedPackage.Version] = state.EVR.Value
		}
	}
	check := test.Check
	if check == "" {
		check = "at least one"
	}
	if check == "all" {
		if matched == len(installed) {
			return ovalResult{state: "true", items: items}
		}
		return ovalResult{state: "false"}
	}
	if check != "at least one" {
		return ovalResult{state: "unknown"}
	}
	if matched > 0 {
		return ovalResult{state: "true", items: items}
	}
	return ovalResult{state: "false"}
}

func combineOVAL(children []ovalResult, operator string) ovalResult {
	if len(children) == 0 {
		return ovalResult{state: "unknown"}
	}
	if operator == "" {
		operator = "AND"
	}
	unknown := false
	items := make(map[string]string)
	if operator == "AND" {
		for _, child := range children {
			if child.state == "false" {
				return ovalResult{state: "false"}
			}
			if child.state != "true" {
				unknown = true
				continue
			}
			for key, value := range child.items {
				items[key] = value
			}
		}
		if unknown {
			return ovalResult{state: "unknown"}
		}
		return ovalResult{state: "true", items: items}
	}
	if operator == "OR" {
		for _, child := range children {
			if child.state == "true" {
				for key, value := range child.items {
					items[key] = value
				}
				continue
			}
			if child.state == "unknown" {
				unknown = true
			}
		}
		if len(items) > 0 {
			return ovalResult{state: "true", items: items}
		}
		if unknown {
			return ovalResult{state: "unknown"}
		}
		return ovalResult{state: "false"}
	}
	return ovalResult{state: "unknown"}
}

func negateOVAL(value ovalResult) ovalResult {
	switch value.state {
	case "true":
		return ovalResult{state: "false"}
	case "false":
		return ovalResult{state: "true"}
	default:
		return ovalResult{state: "unknown"}
	}
}

func compareRPMEVR(installed, threshold, operation string) (bool, error) {
	comparison, err := version.RPM(installed, threshold)
	if err != nil {
		return false, err
	}
	switch operation {
	case "less than":
		return comparison < 0, nil
	case "less than or equal":
		return comparison <= 0, nil
	case "greater than":
		return comparison > 0, nil
	case "greater than or equal":
		return comparison >= 0, nil
	case "equals":
		return comparison == 0, nil
	case "not equal":
		return comparison != 0, nil
	default:
		return false, fmt.Errorf("unsupported RPM OVAL operation %q", operation)
	}
}

var severityPattern = regexp.MustCompile(`(?i)critical|important|moderate|medium|low`)

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "CRITICAL"
	case "important", "high":
		return "HIGH"
	case "moderate", "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		if value == "" || !severityPattern.MatchString(value) {
			return "UNKNOWN"
		}
		return "UNKNOWN"
	}
}
