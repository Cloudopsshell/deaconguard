package ciout

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"deaconguard/internal/checks"
	"deaconguard/internal/scan"
)

var vulnerabilities = []scan.Vulnerability{
	{Finding: checks.Finding{Rule: "CVE-2023-44487", Severity: "HIGH", Title: "nginx:1.27: nghttp2 1.52.0 (Debian 12): CVE-2023-44487",
		Detail: "Fixed in 1.52.0-1+deb12u1: update the image. Known to be exploited (CISA KEV)."}, Fixable: true, Exploited: true},
	{Finding: checks.Finding{Rule: "CVE-2024-1", Severity: "LOW", Title: "nginx:1.27: zlib 1.2.13 (Debian 12): CVE-2024-1", Detail: "No fixed version yet."}},
	{Finding: checks.Finding{Rule: "CVE-2024-1", Severity: "LOW", Title: "nginx:1.27: zlib1g 1.2.13 (Debian 12): CVE-2024-1", Detail: "No fixed version yet."}},
}

func TestSARIF(t *testing.T) {
	data, err := SARIF(ImageItems("nginx:1.27", vulnerabilities))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Fingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	run := document.Runs[0]
	if document.Version != "2.1.0" || run.Tool.Driver.Name != "DeaconGuard" || len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 3 {
		t.Fatalf("document: %s", data)
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "8.0" || run.Results[0].Level != "error" || run.Results[1].Level != "note" {
		t.Errorf("severity: %s", data)
	}
	if run.Results[2].RuleIndex != 1 || run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "nginx-1.27" {
		t.Errorf("rule index or location: %s", data)
	}
	if run.Results[1].Fingerprints["deaconguard/v1"] == run.Results[2].Fingerprints["deaconguard/v1"] {
		t.Error("two packages with the same CVE share a fingerprint")
	}
	if !strings.Contains(run.Results[0].Message.Text, "nghttp2 1.52.0 (Debian 12): CVE-2023-44487 in nginx:1.27") {
		t.Errorf("message: %s", run.Results[0].Message.Text)
	}
	empty, _ := SARIF(ImageItems("scratch", nil))
	if !strings.Contains(string(empty), `"results": []`) {
		t.Errorf("no vulnerabilities: %s", empty)
	}
}

func TestJUnit(t *testing.T) {
	data, err := JUnit("nginx:1.27", ImageItems("nginx:1.27", vulnerabilities), func(item Item) bool { return item.Severity == "HIGH" })
	if err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(data, &suites); err != nil {
		t.Fatal(err)
	}
	suite := suites.Suites[0]
	if suites.Tests != 3 || suites.Failures != 1 || suite.Cases[0].Failure == nil || suite.Cases[1].Failure != nil ||
		suite.Cases[0].Failure.Type != "HIGH" || !strings.HasPrefix(string(data), "<?xml") {
		t.Fatalf("junit: %s", data)
	}
	none, _ := JUnit("scratch", nil, func(Item) bool { return true })
	if !strings.Contains(string(none), `tests="1" failures="0"`) || !strings.Contains(string(none), "Nothing found") {
		t.Errorf("no vulnerabilities: %s", none)
	}
}
