package advisory

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"

	"opsarmor/internal/inventory"
	"opsarmor/internal/platform"
	"opsarmor/internal/version"
)

const maxUbuntuOVALBytes = 384 << 20

type ovalNode struct {
	Name     string
	Text     string
	Attrs    map[string]string
	Children []*ovalNode
}

func (node *ovalNode) attr(name string) string {
	if node == nil {
		return ""
	}
	return node.Attrs[name]
}

func (node *ovalNode) child(name string) *ovalNode {
	if node == nil {
		return nil
	}
	for _, item := range node.Children {
		if item.Name == name {
			return item
		}
	}
	return nil
}

func (node *ovalNode) children(name string) []*ovalNode {
	if node == nil {
		return nil
	}
	result := make([]*ovalNode, 0)
	for _, item := range node.Children {
		if item.Name == name {
			result = append(result, item)
		}
	}
	return result
}

func (node *ovalNode) value() string {
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.Text)
}

type triState uint8

const (
	stateUnknown triState = iota
	stateFalse
	stateTrue
)

type ovalEval struct {
	state triState
	items map[string]string
}

type ubuntuOVALEvaluator struct {
	byID            map[string]*ovalNode
	definitions     map[string]*ovalNode
	packages        map[string][]inventory.Package
	kernel          string
	variables       map[string][]string
	variableUnknown map[string]bool
	tests           map[string]ovalEval
}

func EvaluateUbuntuOVAL(compressed []byte, target platform.Platform, packages []inventory.Package, kernel string) (DebianEvaluation, error) {
	if target.Family != platform.Ubuntu {
		return DebianEvaluation{}, fmt.Errorf("Canonical OVAL cannot evaluate %s", target.Family)
	}
	reader := io.LimitReader(bzip2.NewReader(bytes.NewReader(compressed)), maxUbuntuOVALBytes+1)
	contents, err := io.ReadAll(reader)
	if err != nil {
		return DebianEvaluation{}, fmt.Errorf("decompress Canonical OVAL data: %w", err)
	}
	if len(contents) == 0 || len(contents) > maxUbuntuOVALBytes {
		return DebianEvaluation{}, fmt.Errorf("Canonical OVAL data is empty or exceeds %d bytes", maxUbuntuOVALBytes)
	}
	return evaluateUbuntuOVALXML(contents, packages, kernel)
}

func evaluateUbuntuOVALXML(contents []byte, packages []inventory.Package, kernel string) (DebianEvaluation, error) {
	root, err := parseOVALTree(contents)
	if err != nil {
		return DebianEvaluation{}, fmt.Errorf("parse Canonical OVAL XML: %w", err)
	}
	evaluator := &ubuntuOVALEvaluator{
		byID: make(map[string]*ovalNode), definitions: make(map[string]*ovalNode),
		packages: make(map[string][]inventory.Package), kernel: kernel,
		variables: make(map[string][]string), variableUnknown: make(map[string]bool),
		tests: make(map[string]ovalEval),
	}
	indexOVALNodes(root, evaluator.byID, evaluator.definitions)
	for _, item := range packages {
		evaluator.packages[item.Name] = append(evaluator.packages[item.Name], item)
	}
	result := DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}
	unsupported := make(map[string]bool)
	for _, definition := range evaluator.definitions {
		if definition.attr("class") != "vulnerability" {
			continue
		}
		metadata := definition.child("metadata")
		if metadata == nil {
			continue
		}
		references := make([]*ovalNode, 0)
		for _, reference := range metadata.children("reference") {
			if reference.attr("source") == "CVE" {
				references = append(references, reference)
			}
		}
		if len(references) == 0 {
			continue
		}
		result.Evaluated++
		evaluation := evaluator.criteria(definition.child("criteria"), 0)
		if evaluation.state == stateUnknown {
			for _, reference := range references {
				id := reference.attr("ref_id")
				if !unsupported[id] {
					unsupported[id] = true
					result.Unsupported = append(result.Unsupported, Unsupported{
						ID: id, Title: metadata.child("title").value(),
						Reason: "OVAL rule contains checks not supported by the Go evaluator",
					})
				}
			}
			continue
		}
		if evaluation.state != stateTrue {
			continue
		}
		itemKeys := make([]string, 0, len(evaluation.items))
		for key := range evaluation.items {
			itemKeys = append(itemKeys, key)
		}
		for _, reference := range references {
			for _, key := range itemKeys {
				parts := strings.SplitN(key, "\x00", 2)
				packageName, installedVersion := parts[0], "unknown"
				if len(parts) == 2 {
					installedVersion = parts[1]
				}
				cveURL := reference.attr("ref_url")
				if cveURL == "" {
					cveURL = "https://ubuntu.com/security/" + reference.attr("ref_id")
				}
				result.Findings = append(result.Findings, Finding{
					ID: reference.attr("ref_id"), Package: packageName, InstalledVersion: installedVersion,
					FixedVersion: evaluation.items[key], Severity: ubuntuSeverity(metadata),
					URL: cveURL, Title: metadata.child("title").value(),
				})
			}
		}
	}
	return result, nil
}

func parseOVALTree(contents []byte) (*ovalNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(contents))
	var root *ovalNode
	stack := make([]*ovalNode, 0, 32)
	count := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			count++
			if count > 4_000_000 || len(stack) > 256 {
				return nil, fmt.Errorf("OVAL XML exceeds structural limits")
			}
			node := &ovalNode{Name: value.Name.Local, Attrs: make(map[string]string)}
			for _, attribute := range value.Attr {
				node.Attrs[attribute.Name.Local] = attribute.Value
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("OVAL XML contains multiple root elements")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.CharData:
			if len(stack) != 0 {
				stack[len(stack)-1].Text += string(value)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("unexpected OVAL XML closing element")
			}
			stack = stack[:len(stack)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, fmt.Errorf("OVAL XML is incomplete")
	}
	return root, nil
}

func indexOVALNodes(node *ovalNode, byID, definitions map[string]*ovalNode) {
	if id := node.attr("id"); id != "" {
		byID[id] = node
		if node.Name == "definition" {
			definitions[id] = node
		}
	}
	for _, child := range node.Children {
		indexOVALNodes(child, byID, definitions)
	}
}

func (evaluator *ubuntuOVALEvaluator) criteria(node *ovalNode, depth int) ovalEval {
	if node == nil || depth > 16 {
		return ovalEval{state: stateUnknown}
	}
	children := make([]ovalEval, 0, len(node.Children))
	for _, child := range node.Children {
		switch child.Name {
		case "criterion":
			value := evaluator.test(child.attr("test_ref"))
			if child.attr("negate") == "true" {
				value = negate(value)
			}
			children = append(children, value)
		case "extend_definition":
			definition := evaluator.definitions[child.attr("definition_ref")]
			if definition == nil {
				children = append(children, ovalEval{state: stateUnknown})
				continue
			}
			if definition.attr("class") == "inventory" {
				children = append(children, ovalEval{state: stateTrue})
			} else {
				children = append(children, evaluator.criteria(definition.child("criteria"), depth+1))
			}
		case "criteria":
			value := evaluator.criteria(child, depth+1)
			if child.attr("negate") == "true" {
				value = negate(value)
			}
			children = append(children, value)
		}
	}
	result := combineUbuntu(children, node.attr("operator"))
	if node.attr("negate") == "true" {
		return negate(result)
	}
	return result
}

func (evaluator *ubuntuOVALEvaluator) test(id string) ovalEval {
	if result, ok := evaluator.tests[id]; ok {
		return result
	}
	test := evaluator.byID[id]
	if test == nil {
		return ovalEval{state: stateUnknown}
	}
	objectRef := test.child("object")
	stateRef := test.child("state")
	object := (*ovalNode)(nil)
	state := (*ovalNode)(nil)
	if objectRef != nil {
		object = evaluator.byID[objectRef.attr("object_ref")]
	}
	if stateRef != nil {
		state = evaluator.byID[stateRef.attr("state_ref")]
	}
	var result ovalEval
	switch test.Name {
	case "dpkginfo_test":
		result = evaluator.dpkgTest(test, object, state)
	case "uname_test":
		result = evaluator.unameTest(state)
	case "variable_test":
		result = evaluator.variableTest(test, object, state)
	case "family_test":
		result = ovalEval{state: stateTrue}
	default:
		result = ovalEval{state: stateUnknown}
	}
	evaluator.tests[id] = result
	return result
}

func (evaluator *ubuntuOVALEvaluator) dpkgTest(test, object, state *ovalNode) ovalEval {
	nameField := object.child("name")
	if nameField == nil {
		return ovalEval{state: stateUnknown}
	}
	packageNames := []string{nameField.value()}
	if ref := nameField.attr("var_ref"); ref != "" {
		values, known := evaluator.variable(ref)
		if !known || len(values) == 0 {
			return ovalEval{state: stateUnknown}
		}
		packageNames = values
	}
	installed := make([]inventory.Package, 0)
	allNamesExist := true
	for _, name := range packageNames {
		items := evaluator.packages[name]
		if len(items) == 0 {
			allNamesExist = false
		}
		installed = append(installed, items...)
	}
	checkExistence := test.attr("check_existence")
	if checkExistence == "" {
		checkExistence = "at_least_one_exists"
	}
	if checkExistence == "all_exist" && !allNamesExist || checkExistence == "at_least_one_exists" && len(installed) == 0 {
		return ovalEval{state: stateFalse}
	}
	if checkExistence != "all_exist" && checkExistence != "at_least_one_exists" {
		return ovalEval{state: stateUnknown}
	}
	items := make(map[string]string)
	for _, item := range installed {
		match, fixed, known := compareState(item.Version, state, "evr")
		if !known {
			return ovalEval{state: stateUnknown}
		}
		if match {
			items[item.Name+"\x00"+item.Version] = fixed
		}
	}
	check := test.attr("check")
	if check == "" {
		check = "at least one"
	}
	if check == "all" {
		if len(installed) > 0 && len(items) == len(installed) {
			return ovalEval{state: stateTrue, items: items}
		}
		return ovalEval{state: stateFalse}
	}
	if check != "at least one" {
		return ovalEval{state: stateUnknown}
	}
	if len(items) > 0 {
		return ovalEval{state: stateTrue, items: items}
	}
	return ovalEval{state: stateFalse}
}

func (evaluator *ubuntuOVALEvaluator) unameTest(state *ovalNode) ovalEval {
	condition := state.child("os_release")
	if condition == nil || evaluator.kernel == "" {
		return ovalEval{state: stateUnknown}
	}
	matched, known := compareValue(evaluator.kernel, condition.value(), condition.attr("operation"), "")
	if !known {
		return ovalEval{state: stateUnknown}
	}
	if matched {
		return ovalEval{state: stateTrue, items: map[string]string{"running kernel\x00" + evaluator.kernel: ""}}
	}
	return ovalEval{state: stateFalse}
}

func (evaluator *ubuntuOVALEvaluator) variableTest(test, object, state *ovalNode) ovalEval {
	variableRef := object.child("var_ref")
	if variableRef == nil {
		return ovalEval{state: stateUnknown}
	}
	values, known := evaluator.variable(variableRef.value())
	if !known || len(values) == 0 {
		return ovalEval{state: stateUnknown}
	}
	matchedItems := make(map[string]string)
	matchedCount := 0
	for _, value := range values {
		matched, fixed, isKnown := compareState(value, state, "value")
		if !isKnown {
			return ovalEval{state: stateUnknown}
		}
		if matched {
			matchedCount++
			matchedItems["running kernel\x00"+value] = fixed
		}
	}
	check := test.attr("check")
	if check == "all" && matchedCount == len(values) || check == "at least one" && matchedCount > 0 {
		return ovalEval{state: stateTrue, items: matchedItems}
	}
	if check == "all" || check == "at least one" {
		return ovalEval{state: stateFalse}
	}
	return ovalEval{state: stateUnknown}
}

func (evaluator *ubuntuOVALEvaluator) variable(id string) ([]string, bool) {
	if values, exists := evaluator.variables[id]; exists {
		return values, true
	}
	if evaluator.variableUnknown[id] {
		return nil, false
	}
	variable := evaluator.byID[id]
	if variable == nil {
		evaluator.variableUnknown[id] = true
		return nil, false
	}
	var values []string
	var known bool
	switch variable.Name {
	case "constant_variable":
		for _, value := range variable.children("value") {
			values = append(values, value.value())
		}
		known = len(values) > 0
	case "local_variable":
		var component *ovalNode
		if len(variable.Children) > 0 {
			component = variable.Children[0]
		}
		values, known = evaluator.component(component)
	}
	if known {
		evaluator.variables[id] = values
		return values, true
	}
	evaluator.variableUnknown[id] = true
	return nil, false
}

func (evaluator *ubuntuOVALEvaluator) component(node *ovalNode) ([]string, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Name {
	case "literal_component":
		return []string{node.value()}, true
	case "concat":
		var builder strings.Builder
		for _, child := range node.Children {
			values, known := evaluator.component(child)
			if !known || len(values) != 1 {
				return nil, false
			}
			builder.WriteString(values[0])
		}
		return []string{builder.String()}, true
	case "regex_capture":
		objectComponent := node.child("object_component")
		if objectComponent == nil || objectComponent.attr("item_field") != "os_release" || evaluator.kernel == "" {
			return nil, false
		}
		pattern, err := regexp.Compile(node.attr("pattern"))
		if err != nil {
			return nil, false
		}
		match := pattern.FindStringSubmatch(evaluator.kernel)
		if len(match) < 2 {
			return nil, false
		}
		return []string{match[1]}, true
	default:
		return nil, false
	}
}

func compareState(value string, state *ovalNode, field string) (bool, string, bool) {
	if state == nil {
		return true, "", true
	}
	conditions := state.children(field)
	if len(conditions) == 0 {
		return false, "", false
	}
	fixed := ""
	for _, condition := range conditions {
		matched, known := compareValue(value, condition.value(), condition.attr("operation"), condition.attr("datatype"))
		if !known {
			return false, "", false
		}
		if !matched {
			return false, "", true
		}
		if condition.attr("operation") == "less than" && fixed == "" {
			fixed = condition.value()
		}
	}
	return true, fixed, true
}

func compareValue(value, threshold, operation, datatype string) (bool, bool) {
	if operation == "pattern match" {
		pattern, err := regexp.Compile(threshold)
		if err != nil {
			return false, false
		}
		return pattern.MatchString(value), true
	}
	comparison := strings.Compare(value, threshold)
	if datatype == "debian_evr_string" {
		var err error
		comparison, err = version.Debian(value, threshold)
		if err != nil {
			return false, false
		}
	}
	switch operation {
	case "less than":
		return comparison < 0, true
	case "less than or equal":
		return comparison <= 0, true
	case "greater than":
		return comparison > 0, true
	case "greater than or equal":
		return comparison >= 0, true
	case "equals":
		return comparison == 0, true
	case "not equal":
		return comparison != 0, true
	default:
		return false, false
	}
}

func combineUbuntu(children []ovalEval, operator string) ovalEval {
	if len(children) == 0 {
		return ovalEval{state: stateUnknown}
	}
	if operator == "" {
		operator = "AND"
	}
	items := make(map[string]string)
	unknown := false
	if operator == "AND" {
		for _, child := range children {
			if child.state == stateFalse {
				return ovalEval{state: stateFalse}
			}
			if child.state == stateUnknown {
				unknown = true
				continue
			}
			for key, value := range child.items {
				items[key] = value
			}
		}
		if unknown {
			return ovalEval{state: stateUnknown}
		}
		return ovalEval{state: stateTrue, items: items}
	}
	if operator == "OR" {
		for _, child := range children {
			if child.state == stateTrue {
				for key, value := range child.items {
					items[key] = value
				}
			} else if child.state == stateUnknown {
				unknown = true
			}
		}
		if len(items) > 0 {
			return ovalEval{state: stateTrue, items: items}
		}
		if unknown {
			return ovalEval{state: stateUnknown}
		}
		return ovalEval{state: stateFalse}
	}
	return ovalEval{state: stateUnknown}
}

func negate(value ovalEval) ovalEval {
	switch value.state {
	case stateTrue:
		return ovalEval{state: stateFalse}
	case stateFalse:
		return ovalEval{state: stateTrue}
	default:
		return ovalEval{state: stateUnknown}
	}
}

func ubuntuSeverity(metadata *ovalNode) string {
	for _, cve := range metadata.child("advisory").children("cve") {
		if severity := normalizeSeverity(cve.attr("cvss_severity")); severity != "UNKNOWN" {
			return severity
		}
		if severity := normalizeSeverity(cve.attr("priority")); severity != "UNKNOWN" {
			return severity
		}
	}
	return "UNKNOWN"
}
