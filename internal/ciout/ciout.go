// Package ciout writes an image check for CI systems: SARIF 2.1.0, which
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

// title is a finding's title without the image name in front.
func title(image string, v scan.Vulnerability) string {
	return strings.TrimPrefix(v.Title, image+": ")
}

// helpURI links a vulnerability's ID; OSV knows CVEs and GHSAs alike.
func helpURI(id string) string { return "https://osv.dev/vulnerability/" + id }

// artifact is the image as a SARIF location: a relative path, since a
// colon would read as a URI scheme.
func artifact(image string) string {
	return strings.NewReplacer(":", "-", "@", "-", " ", "-").Replace(strings.TrimLeft(image, "/"))
}

// SARIF writes the vulnerabilities as one SARIF 2.1.0 run.
func SARIF(image string, vulnerabilities []scan.Vulnerability) ([]byte, error) {
	type message struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID                   string         `json:"id"`
		Name                 string         `json:"name"`
		ShortDescription     message        `json:"shortDescription"`
		FullDescription      message        `json:"fullDescription"`
		HelpURI              string         `json:"helpUri"`
		Help                 message        `json:"help"`
		DefaultConfiguration map[string]any `json:"defaultConfiguration"`
		Properties           map[string]any `json:"properties"`
	}
	rules := []rule{}
	results := []map[string]any{}
	index := map[string]int{}
	for _, v := range vulnerabilities {
		severity := strings.ToUpper(v.Severity)
		if _, seen := index[v.Rule]; !seen {
			properties := map[string]any{"tags": []string{"security", "vulnerability", strings.ToLower(severity)}}
			if score, ok := securitySeverity[severity]; ok {
				properties["security-severity"] = score
			}
			index[v.Rule] = len(rules)
			rules = append(rules, rule{
				ID: v.Rule, Name: v.Rule,
				ShortDescription:     message{Text: v.Rule},
				FullDescription:      message{Text: title(image, v)},
				HelpURI:              helpURI(v.Rule),
				Help:                 message{Text: v.Detail},
				DefaultConfiguration: map[string]any{"level": level(severity)},
				Properties:           properties,
			})
		}
		fingerprint := sha256.Sum256([]byte(image + "\x00" + v.Rule + "\x00" + title(image, v)))
		results = append(results, map[string]any{
			"ruleId":    v.Rule,
			"ruleIndex": index[v.Rule],
			"level":     level(severity),
			"message":   message{Text: fmt.Sprintf("%s in %s. %s", title(image, v), image, v.Detail)},
			"locations": []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": artifact(image)},
				"region":           map[string]int{"startLine": 1},
			}}},
			"partialFingerprints": map[string]string{"deaconguard/v1": hex.EncodeToString(fingerprint[:16])},
			"properties":          map[string]any{"fixable": v.Fixable, "knownExploited": v.Exploited, "severity": severity},
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

// JUnit writes the vulnerabilities as test cases of one suite: those that
// failing selects, such as those at or above --fail-on, fail; the others
// pass, so the report lists them too. With none, one passing case says so.
func JUnit(image string, vulnerabilities []scan.Vulnerability, failing func(scan.Vulnerability) bool) ([]byte, error) {
	suite := junitSuite{Name: "DeaconGuard: " + image}
	for _, v := range vulnerabilities {
		c := junitCase{Name: title(image, v), ClassName: image}
		if failing(v) {
			text := v.Detail
			if !strings.Contains(text, helpURI(v.Rule)) {
				text += "\n" + helpURI(v.Rule)
			}
			c.Failure = &junitFailure{Message: strings.ToUpper(v.Severity) + ": " + v.Rule, Type: strings.ToUpper(v.Severity), Text: text}
			suite.Failures++
		}
		suite.Cases = append(suite.Cases, c)
	}
	if len(suite.Cases) == 0 {
		suite.Cases = append(suite.Cases, junitCase{Name: "No vulnerabilities found", ClassName: image})
	}
	suite.Tests = len(suite.Cases)
	document := junitSuites{Name: "DeaconGuard", Tests: suite.Tests, Failures: suite.Failures, Suites: []junitSuite{suite}}
	encoded, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(encoded, '\n')...), nil
}
