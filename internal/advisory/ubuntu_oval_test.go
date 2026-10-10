package advisory

import (
	"io"
	"strings"
	"testing"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
)

func TestEvaluateUbuntuOVALFindsVulnerableDpkgPackage(t *testing.T) {
	oval := []byte(`<oval_definitions>
  <definitions><definition id="oval:ubuntu:def:1" class="vulnerability">
    <metadata><title>Example Ubuntu issue</title><reference source="CVE" ref_id="CVE-2025-1234" ref_url="https://ubuntu.com/security/CVE-2025-1234"/><advisory><cve cvss_severity="High"/></advisory></metadata>
    <criteria operator="AND"><criterion test_ref="oval:ubuntu:tst:1"/></criteria>
  </definition></definitions>
  <tests><dpkginfo_test id="oval:ubuntu:tst:1" check="at least one" check_existence="at_least_one_exists">
    <object object_ref="oval:ubuntu:obj:1"/><state state_ref="oval:ubuntu:ste:1"/>
  </dpkginfo_test></tests>
  <objects><dpkginfo_object id="oval:ubuntu:obj:1"><name>example</name></dpkginfo_object></objects>
  <states><dpkginfo_state id="oval:ubuntu:ste:1"><evr datatype="debian_evr_string" operation="less than">2.0-1ubuntu1</evr></dpkginfo_state></states>
</oval_definitions>`)
	result, err := evaluateUbuntuOVALXML(oval, []inventory.Package{{Name: "example", Version: "2.0-1ubuntu0", Source: "example"}}, "6.8.0-1013-aws")
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 1 || len(result.Findings) != 1 {
		t.Fatalf("unexpected Ubuntu OVAL evaluation: %+v", result)
	}
	if result.Findings[0].FixedVersion != "2.0-1ubuntu1" || result.Findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected Ubuntu OVAL finding: %+v", result.Findings[0])
	}
}

func TestEvaluateUbuntuOVALSurfacesUnknownTests(t *testing.T) {
	oval := []byte(`<oval_definitions><definitions><definition id="oval:ubuntu:def:2" class="vulnerability">
  <metadata><title>Unknown check</title><reference source="CVE" ref_id="CVE-2025-5678"/></metadata>
  <criteria operator="AND"><criterion test_ref="missing:test"/></criteria>
</definition></definitions></oval_definitions>`)
	result, err := evaluateUbuntuOVALXML(oval, []inventory.Package{{Name: "example", Version: "1.0", Source: "example"}}, "6.8.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Unsupported) != 1 || result.Unsupported[0].ID != "CVE-2025-5678" {
		t.Fatalf("unknown OVAL test was not surfaced: %+v", result)
	}
	_ = platform.Ubuntu
}

func TestOVALParserKeepsOnlyWhatTheEvaluationReads(t *testing.T) {
	root, err := parseOVALTree(strings.NewReader(`<oval_definitions>
  <definitions>
    <definition id="oval:1" class="vulnerability" version="3">
      <metadata><title>  CVE-2026-1 in example  </title><description>a very long text</description></metadata>
      <criteria operator="AND"><criterion test_ref="oval:2" comment="a long comment"/></criteria>
    </definition>
  </definitions>
</oval_definitions>`))
	if err != nil {
		t.Fatal(err)
	}
	definition := root.child("definitions").child("definition")
	if definition.attr("id") != "oval:1" || definition.attr("version") != "" {
		t.Fatalf("attributes = %+v", definition.Attrs)
	}
	metadata := definition.child("metadata")
	if metadata.child("title").value() != "CVE-2026-1 in example" || metadata.child("description") != nil || metadata.Text != "" {
		t.Fatalf("metadata = %+v", metadata)
	}
	criterion := definition.child("criteria").child("criterion")
	if criterion.attr("test_ref") != "oval:2" || criterion.attr("comment") != "" {
		t.Fatalf("criterion = %+v", criterion.Attrs)
	}
}

func TestOVALDataLargerThanTheLimitIsRefused(t *testing.T) {
	limited := &limitedReader{reader: strings.NewReader(strings.Repeat("x", 100)), remaining: 10}
	if _, err := io.ReadAll(limited); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ReadAll() error = %v", err)
	}
	exact := &limitedReader{reader: strings.NewReader(strings.Repeat("x", 10)), remaining: 10}
	if data, err := io.ReadAll(exact); err != nil || len(data) != 10 {
		t.Fatalf("ReadAll() = %d bytes, %v", len(data), err)
	}
}
