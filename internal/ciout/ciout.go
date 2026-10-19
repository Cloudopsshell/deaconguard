// Package ciout writes check results for CI systems: SARIF 2.1.0, which
// GitHub code scanning, GitLab and Azure DevOps read, and JUnit XML, which
// GitLab, Jenkins, Bitbucket and Azure DevOps show as test results.
package ciout

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/scan"
)

// Item is one result: a vulnerability, or a finding in a file.
type Item struct {
	Rule     string
	Severity string
	// Title says what and where, in one line; Detail what to do.
	Title  string
	Detail string
	// Help is the rule's longer description, HelpURI where to read more.
	Help    string
	HelpURI string
	// URI is the file or image, relative; Line its line, from 1.
	URI  string
	Line int
	// Group is the JUnit class name: the image or file.
	Group      string
	Properties map[string]any
}

// securitySeverity is the score GitHub sorts and filters alerts by.
var securitySeverity = map[string]string{"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "2.0"}

func level(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	}
	return "note"
}

// SARIF writes items as one SARIF 2.1.0 run, with a rule per rule ID.
func SARIF(items []Item) ([]byte, error) {
	type message struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID                   string         `json:"id"`
		Name                 string         `json:"name"`
		ShortDescription     message        `json:"shortDescription"`
		FullDescription      message        `json:"fullDescription"`
		HelpURI              string         `json:"helpUri,omitempty"`
		Help                 message        `json:"help"`
		DefaultConfiguration map[string]any `json:"defaultConfiguration"`
		Properties           map[string]any `json:"properties"`
	}
	rules := []rule{}
	results := []map[string]any{}
	index := map[string]int{}
	for _, item := range items {
		severity := strings.ToUpper(item.Severity)
		if _, seen := index[item.Rule]; !seen {
			properties := map[string]any{"tags": []string{"security", strings.ToLower(severity)}}
			if score, ok := securitySeverity[severity]; ok {
				properties["security-severity"] = score
			}
			help := item.Help
			if help == "" {
				help = item.Detail
			}
			index[item.Rule] = len(rules)
			rules = append(rules, rule{
				ID: item.Rule, Name: item.Rule,
				ShortDescription:     message{Text: item.Rule},
				FullDescription:      message{Text: item.Title},
				HelpURI:              item.HelpURI,
				Help:                 message{Text: help},
				DefaultConfiguration: map[string]any{"level": level(severity)},
				Properties:           properties,
			})
		}
		line := item.Line
		if line < 1 {
			line = 1
		}
		fingerprint := sha256.Sum256([]byte(item.URI + "\x00" + item.Rule + "\x00" + item.Title))
		properties := map[string]any{"severity": severity}
		for key, value := range item.Properties {
			properties[key] = value
		}
		results = append(results, map[string]any{
			"ruleId":    item.Rule,
			"ruleIndex": index[item.Rule],
			"level":     level(severity),
			"message":   message{Text: strings.TrimSpace(item.Title + ". " + item.Detail)},
			"locations": []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": item.URI},
				"region":           map[string]int{"startLine": line},
			}}},
			"partialFingerprints": map[string]string{"deaconguard/v1": hex.EncodeToString(fingerprint[:16])},
			"properties":          properties,
		})
	}
	document := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name": "DeaconGuard", "version": buildinfo.Get().Version, "informationUri": "https://deaconguard.io", "rules": rules,
			}},
			"results": results,
		}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(document)
	return out.Bytes(), err
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

// JUnit writes items as test cases of one suite: those that failing
// selects, such as those at or above --fail-on, fail; the others pass, so
// the report lists them too. With none, one passing case says so.
func JUnit(suiteName string, items []Item, failing func(Item) bool) ([]byte, error) {
	suite := junitSuite{Name: "DeaconGuard: " + suiteName}
	for _, item := range items {
		c := junitCase{Name: item.Title, ClassName: item.Group}
		if failing(item) {
			text := item.Detail
			if item.HelpURI != "" && !strings.Contains(text, item.HelpURI) {
				text += "\n" + item.HelpURI
			}
			severity := strings.ToUpper(item.Severity)
			c.Failure = &junitFailure{Message: severity + ": " + item.Rule, Type: severity, Text: text}
			suite.Failures++
		}
		suite.Cases = append(suite.Cases, c)
	}
	if len(suite.Cases) == 0 {
		suite.Cases = append(suite.Cases, junitCase{Name: "Nothing found", ClassName: suiteName})
	}
	suite.Tests = len(suite.Cases)
	document := junitSuites{Name: "DeaconGuard", Tests: suite.Tests, Failures: suite.Failures, Suites: []junitSuite{suite}}
	encoded, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(encoded, '\n')...), nil
}

// ImageItems turns an image's vulnerabilities into items. The image is the
// location, as a relative path, since a colon would read as a URI scheme.
func ImageItems(image string, vulnerabilities []scan.Vulnerability) []Item {
	uri := strings.NewReplacer(":", "-", "@", "-", " ", "-").Replace(strings.TrimLeft(image, "/"))
	items := make([]Item, 0, len(vulnerabilities))
	for _, v := range vulnerabilities {
		title := strings.TrimPrefix(v.Title, image+": ")
		items = append(items, Item{
			Rule: v.Rule, Severity: v.Severity, Title: fmt.Sprintf("%s in %s", title, image), Detail: v.Detail,
			Help: title + ". " + v.Detail, HelpURI: "https://osv.dev/vulnerability/" + v.Rule,
			URI: uri, Line: 1, Group: image,
			Properties: map[string]any{"fixable": v.Fixable, "knownExploited": v.Exploited},
		})
	}
	return items
}
