package advisory

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"deaconguard/internal/inventory"
)

// The OVAL feeds of AlmaLinux, Oracle Linux and SUSE describe packages with
// rpminfo tests like Red Hat's, but also test who signed a package, its
// version, release and architecture, and (AlmaLinux) which release package
// is installed. evaluateRPMFamilyOVAL reads them as a stream, since SUSE's
// is a few hundred megabytes of XML.

type familyDefinition struct {
	Class    string `xml:"class,attr"`
	Metadata struct {
		Title      string          `xml:"title"`
		References []ovalReference `xml:"reference"`
		Advisory   struct {
			SeverityAttribute string `xml:"severity,attr"`
			Severity          string `xml:"severity"`
			CVEs              []struct {
				Text  string `xml:",chardata"`
				CVSS3 string `xml:"cvss3,attr"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria ovalCriteria `xml:"criteria"`
}

type familyTest struct {
	ID             string    `xml:"id,attr"`
	Check          string    `xml:"check,attr"`
	CheckExistence string    `xml:"check_existence,attr"`
	Object         ovalRef   `xml:"object"`
	States         []ovalRef `xml:"state"`
	// verifyFile marks an rpmverifyfile test, which AlmaLinux uses to say
	// which release package is installed; its states name the package.
	verifyFile bool
}

type familyObject struct {
	ID   string          `xml:"id,attr"`
	Name ovalObjectField `xml:"name"`
	Arch ovalObjectField `xml:"arch"`
}

type familyField struct {
	Value     string `xml:",chardata"`
	Operation string `xml:"operation,attr"`
}

type familyState struct {
	ID           string       `xml:"id,attr"`
	Name         *familyField `xml:"name"`
	EVR          *familyField `xml:"evr"`
	Version      *familyField `xml:"version"`
	Release      *familyField `xml:"release"`
	Arch         *familyField `xml:"arch"`
	SignatureKey *familyField `xml:"signature_keyid"`
}

type rpmFamilyEvaluator struct {
	packages []inventory.Package
	byName   map[string][]inventory.Package
	tests    map[string]familyTest
	objects  map[string]familyObject
	states   map[string]familyState
	results  map[string]ovalResult
	patterns map[string]*regexp.Regexp
	// vendorKeys are the short (last 8 hex digits) IDs of every key the
	// distribution signs its own packages with; see VendorKeys.
	vendorKeys map[string]bool
	// assumedSigned is set when the inventory has no signing keys, from
	// agents before 0.19.0, and a key test was taken as passed.
	assumedSigned bool
}

// VendorKeys are the keys each family's own packages are signed with, as
// the distribution's base image installs them. A feed's "signed with" test
// names one key, but SUSE signs openSUSE Leap with several (SUSE Linux
// Enterprise's binaries, openSUSE's, and Backports'); a package signed with
// any of them is the vendor's. One signed with another key, from a
// third-party repository, isn't matched against the vendor's advisories.
var VendorKeys = map[string][]string{
	// openSUSE (old and 2023), SUSE (2048 and 4096 bit, and reserves),
	// SUSE 16, ALP's reserve, and openSUSE Backports for 15 and 16.
	"suse": {"3dbdc284", "29b700a4", "39db7c82", "3fa1d6ce", "50a3dd1c", "d588dc46", "09d9ea69", "73f03759", "645bae34", "65176565", "287a0027"},
}

var familyCVE = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// FamilyEvaluation is an evaluation, and whether package signatures had to
// be assumed.
type FamilyEvaluation struct {
	DebianEvaluation
	AssumedSigned bool
}

// evaluateRPMFamilyOVAL evaluates a decompressed OVAL stream against the
// installed packages. Definitions of class vulnerability (one CVE) and patch
// (an advisory and its CVEs) both count; each true one is a finding for each
// of its CVEs and each package it matched.
func evaluateRPMFamilyOVAL(stream io.Reader, packages []inventory.Package, vendorKeys []string) (FamilyEvaluation, error) {
	evaluator := &rpmFamilyEvaluator{
		vendorKeys: make(map[string]bool),
		packages:   packages, byName: make(map[string][]inventory.Package), tests: make(map[string]familyTest),
		objects: make(map[string]familyObject), states: make(map[string]familyState), results: make(map[string]ovalResult),
		patterns: make(map[string]*regexp.Regexp),
	}
	for _, item := range packages {
		evaluator.byName[item.Name] = append(evaluator.byName[item.Name], item)
	}
	for _, key := range vendorKeys {
		evaluator.vendorKeys[strings.ToLower(key)] = true
	}
	decoder := xml.NewDecoder(stream)
	definitions := make([]familyDefinition, 0, 4096)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return FamilyEvaluation{}, fmt.Errorf("read OVAL XML: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "definition":
			var definition familyDefinition
			if err := decoder.DecodeElement(&definition, &start); err != nil {
				return FamilyEvaluation{}, fmt.Errorf("read an OVAL definition: %w", err)
			}
			if definition.Class == "vulnerability" || definition.Class == "patch" {
				definitions = append(definitions, definition)
			}
		case "rpminfo_test", "rpmverifyfile_test":
			var test familyTest
			if err := decoder.DecodeElement(&test, &start); err != nil {
				return FamilyEvaluation{}, fmt.Errorf("read an OVAL test: %w", err)
			}
			test.verifyFile = start.Name.Local == "rpmverifyfile_test"
			evaluator.tests[test.ID] = test
		case "rpminfo_object":
			var object familyObject
			if err := decoder.DecodeElement(&object, &start); err != nil {
				return FamilyEvaluation{}, fmt.Errorf("read an OVAL object: %w", err)
			}
			evaluator.objects[object.ID] = object
		case "rpminfo_state", "rpmverifyfile_state":
			var state familyState
			if err := decoder.DecodeElement(&state, &start); err != nil {
				return FamilyEvaluation{}, fmt.Errorf("read an OVAL state: %w", err)
			}
			evaluator.states[state.ID] = state
		}
	}
	if len(definitions) == 0 {
		return FamilyEvaluation{}, errors.New("the OVAL feed has no vulnerability or patch definitions")
	}

	result := FamilyEvaluation{DebianEvaluation: DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}}
	seen := make(map[string]bool)
	for _, definition := range definitions {
		cves, urls := definitionCVEs(definition)
		// SUSE lists CVEs that don't affect the release with no criteria.
		if len(cves) == 0 || (len(definition.Criteria.Criterion) == 0 && len(definition.Criteria.Criteria) == 0) {
			continue
		}
		result.Evaluated++
		evaluation := evaluator.criteria(definition.Criteria, 0)
		switch evaluation.state {
		case "unknown":
			for _, cve := range cves {
				if !seen["u"+cve] {
					seen["u"+cve] = true
					result.Unsupported = append(result.Unsupported, Unsupported{ID: cve, Title: definition.Metadata.Title,
						Reason: "OVAL rule contains checks not supported by the Go evaluator"})
				}
			}
			continue
		case "false":
			continue
		}
		severity := normalizeSeverity(firstNonEmpty(definition.Metadata.Advisory.Severity, definition.Metadata.Advisory.SeverityAttribute))
		keys := make([]string, 0, len(evaluation.items))
		for key := range evaluation.items {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, cve := range cves {
			score, vector := familyCVSS(definition, cve)
			for _, key := range keys {
				name, installed, _ := strings.Cut(key, "\x00")
				if seen[cve+"\x00"+key] {
					continue
				}
				seen[cve+"\x00"+key] = true
				result.Findings = append(result.Findings, Finding{
					ID: cve, Package: name, InstalledVersion: installed, FixedVersion: strings.TrimPrefix(evaluation.items[key], "0:"),
					Severity: severity, CVSSScore: score, CVSSVector: vector, URL: urls[cve], Title: definition.Metadata.Title,
				})
			}
		}
	}
	result.AssumedSigned = evaluator.assumedSigned
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// definitionCVEs returns a definition's CVEs and a link for each: SUSE
// writes "SUSE CVE-2024-1234" and "Mitre CVE-2024-1234" as references.
func definitionCVEs(definition familyDefinition) ([]string, map[string]string) {
	cves := make([]string, 0)
	urls := make(map[string]string)
	for _, reference := range definition.Metadata.References {
		id := familyCVE.FindString(reference.ID)
		if id == "" {
			continue
		}
		if _, known := urls[id]; !known {
			cves = append(cves, id)
			urls[id] = reference.URL
		}
		// Prefer the distribution's own page over NVD or Mitre.
		if strings.HasPrefix(reference.ID, "SUSE ") || strings.Contains(reference.URL, "oracle.com") {
			urls[id] = reference.URL
		}
	}
	return cves, urls
}

func familyCVSS(definition familyDefinition, cve string) (float64, string) {
	for _, item := range definition.Metadata.Advisory.CVEs {
		if strings.HasPrefix(strings.TrimSpace(item.Text), cve) && item.CVSS3 != "" {
			score, vector, _ := strings.Cut(item.CVSS3, "/")
			return parseCVSS(score, vector)
		}
	}
	return 0, ""
}

func (evaluator *rpmFamilyEvaluator) criteria(criteria ovalCriteria, depth int) ovalResult {
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
		children = append(children, evaluator.criteria(nested, depth+1))
	}
	combined := combineOVAL(children, criteria.Operator)
	if criteria.Negate == "true" {
		return negateOVAL(combined)
	}
	return combined
}

func (evaluator *rpmFamilyEvaluator) test(id string) ovalResult {
	if result, done := evaluator.results[id]; done {
		return result
	}
	result := evaluator.evaluateTest(id)
	evaluator.results[id] = result
	return result
}

func (evaluator *rpmFamilyEvaluator) evaluateTest(id string) ovalResult {
	test, ok := evaluator.tests[id]
	if !ok {
		return ovalResult{state: "unknown"}
	}
	var candidates []inventory.Package
	if test.verifyFile {
		// The states name the package (such as ^almalinux-release); every
		// installed package is a candidate.
		candidates = evaluator.packages
	} else {
		object, ok := evaluator.objects[test.Object.Ref]
		if !ok || object.Name.Value == "" || object.Name.VarRef != "" {
			return ovalResult{state: "unknown"}
		}
		switch object.Name.Operation {
		case "", "equals":
			candidates = evaluator.byName[object.Name.Value]
		case "pattern match":
			for _, item := range evaluator.packages {
				matched, ok := evaluator.match(object.Name.Value, item.Name)
				if !ok {
					return ovalResult{state: "unknown"}
				}
				if matched {
					candidates = append(candidates, item)
				}
			}
		default:
			return ovalResult{state: "unknown"}
		}
	}
	states := make([]familyState, 0, len(test.States))
	for _, reference := range test.States {
		state, ok := evaluator.states[reference.StateRef]
		if !ok {
			return ovalResult{state: "unknown"}
		}
		states = append(states, state)
	}

	satisfied := 0
	items := make(map[string]string)
	for _, candidate := range candidates {
		passes := true
		fixed := ""
		for _, state := range states {
			matched, threshold, ok := evaluator.stateMatches(state, candidate)
			if !ok {
				return ovalResult{state: "unknown"}
			}
			if !matched {
				passes = false
				break
			}
			if threshold != "" {
				fixed = threshold
			}
		}
		if passes {
			satisfied++
			// Only a test that names a fixed version says the package is
			// vulnerable; "is installed" and "is signed" tests only qualify.
			if fixed != "" {
				items[candidate.Name+"\x00"+candidate.Version] = fixed
			}
		}
	}

	existence := test.CheckExistence
	if existence == "" {
		existence = "at_least_one_exists"
	}
	switch existence {
	case "at_least_one_exists", "any_exist":
		if len(candidates) == 0 {
			return ovalResult{state: "false"}
		}
	case "none_exist":
		if len(candidates) == 0 {
			return ovalResult{state: "true", items: map[string]string{}}
		}
		return ovalResult{state: "false"}
	default:
		return ovalResult{state: "unknown"}
	}
	switch test.Check {
	case "", "at least one":
		if satisfied > 0 {
			return ovalResult{state: "true", items: items}
		}
		return ovalResult{state: "false"}
	case "all":
		if satisfied == len(candidates) {
			return ovalResult{state: "true", items: items}
		}
		return ovalResult{state: "false"}
	case "none satisfy":
		if satisfied == 0 {
			return ovalResult{state: "true", items: map[string]string{}}
		}
		return ovalResult{state: "false"}
	default:
		return ovalResult{state: "unknown"}
	}
}

// stateMatches tests one installed package against every field of a state.
// threshold is the version an EVR "less than" names: the fixed version.
func (evaluator *rpmFamilyEvaluator) stateMatches(state familyState, item inventory.Package) (matched bool, threshold string, ok bool) {
	version, release := splitVersionRelease(item.Version)
	checks := []struct {
		field     *familyField
		value     string
		isVersion bool
	}{{state.Name, item.Name, false}, {state.Version, version, true}, {state.Release, release, true}, {state.Arch, item.Arch, false}}
	for _, check := range checks {
		if check.field == nil {
			continue
		}
		value := check.value
		// "+" starts build metadata: openSUSE Leap 16's release package is
		// version 16.0+leap, which its feed tests as ==16.0.
		if check.isVersion && check.field.Operation != "pattern match" {
			if base, _, found := strings.Cut(value, "+"); found {
				value = base
			}
		}
		matched, ok := evaluator.compareText(*check.field, value)
		if !ok {
			return false, "", false
		}
		if !matched {
			return false, "", true
		}
	}
	if state.SignatureKey != nil {
		if item.SigningKey == "" {
			// No key in the inventory: from an older agent. The package is
			// taken to be the distribution's own.
			evaluator.assumedSigned = true
		} else if !strings.EqualFold(strings.TrimSpace(state.SignatureKey.Value), item.SigningKey) && !evaluator.vendorKeys[shortKey(item.SigningKey)] {
			return false, "", true
		}
	}
	if state.EVR != nil {
		matched, err := compareRPMEVR(item.Version, strings.TrimSpace(state.EVR.Value), state.EVR.Operation)
		if err != nil {
			return false, "", false
		}
		if !matched {
			return false, "", true
		}
		if strings.HasPrefix(state.EVR.Operation, "less than") {
			threshold = strings.TrimSpace(state.EVR.Value)
		}
	}
	return true, threshold, true
}

func (evaluator *rpmFamilyEvaluator) compareText(field familyField, value string) (bool, bool) {
	expected := strings.TrimSpace(field.Value)
	switch field.Operation {
	case "", "equals":
		return value == expected, true
	case "not equal":
		return value != expected, true
	case "pattern match":
		return evaluator.match(expected, value)
	default:
		return false, false
	}
}

func (evaluator *rpmFamilyEvaluator) match(pattern, value string) (bool, bool) {
	compiled, cached := evaluator.patterns[pattern]
	if !cached {
		var err error
		if compiled, err = regexp.Compile(pattern); err != nil {
			evaluator.patterns[pattern] = nil
			return false, false
		}
		evaluator.patterns[pattern] = compiled
	}
	if compiled == nil {
		return false, false
	}
	return compiled.MatchString(value), true
}

// splitVersionRelease splits [epoch:]version-release.
func splitVersionRelease(evr string) (string, string) {
	if _, rest, found := strings.Cut(evr, ":"); found {
		evr = rest
	}
	last := strings.LastIndexByte(evr, '-')
	if last < 0 {
		return evr, ""
	}
	return evr[:last], evr[last+1:]
}

// shortKey is the last 8 hex digits of a key ID, as rpm names keys.
func shortKey(key string) string {
	if len(key) > 8 {
		return key[len(key)-8:]
	}
	return key
}
