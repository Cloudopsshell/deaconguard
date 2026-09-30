package advisory

import (
	"testing"

	"deaconguard/internal/inventory"
)

func TestEvaluateRedHatOVALFindsVulnerableRPM(t *testing.T) {
	xmlData := []byte(`<oval_definitions>
  <definitions><definition id="oval:rh:def:1" class="vulnerability">
    <metadata><title>Example RHEL issue</title><reference source="CVE" ref_id="CVE-2025-0001" ref_url="https://access.redhat.com/security/cve/CVE-2025-0001"/><advisory severity="Important"/></metadata>
    <criteria operator="AND"><criterion test_ref="oval:rh:tst:1"/></criteria>
  </definition></definitions>
  <tests><rpminfo_test id="oval:rh:tst:1" check="at least one" check_existence="at_least_one_exists">
    <object object_ref="oval:rh:obj:1"/><state state_ref="oval:rh:ste:1"/>
  </rpminfo_test></tests>
	<objects><rpminfo_object id="oval:rh:obj:1"><name>openssl-libs</name><arch operation="equals">x86_64</arch></rpminfo_object></objects>
  <states><rpminfo_state id="oval:rh:ste:1"><evr datatype="rpm evr string" operation="less than">1:3.2.2-7.el9</evr></rpminfo_state></states>
</oval_definitions>`)
	packages := []inventory.Package{
		{Name: "openssl-libs", Version: "1:3.2.2-6.el9", Source: "openssl", Arch: "x86_64"},
		{Name: "openssl-libs", Version: "1:3.2.2-6.el9", Source: "openssl", Arch: "aarch64"},
	}
	result, err := evaluateRedHatOVALXML(xmlData, packages)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 1 || len(result.Findings) != 1 {
		t.Fatalf("unexpected evaluation: %+v", result)
	}
	finding := result.Findings[0]
	if finding.ID != "CVE-2025-0001" || finding.FixedVersion != "1:3.2.2-7.el9" || finding.Severity != "HIGH" {
		t.Fatalf("unexpected finding: %+v", finding)
	}
}

func TestEvaluateRedHatOVALDoesNotHideUnsupportedTests(t *testing.T) {
	xmlData := []byte(`<oval_definitions>
  <definitions><definition id="oval:rh:def:2" class="vulnerability">
    <metadata><title>Unsupported example</title><reference source="CVE" ref_id="CVE-2025-0002"/></metadata>
    <criteria operator="AND"><criterion test_ref="oval:rh:tst:missing"/></criteria>
  </definition></definitions>
</oval_definitions>`)
	result, err := evaluateRedHatOVALXML(xmlData, []inventory.Package{{Name: "openssl-libs", Version: "1:3.2.2-6.el9", Source: "openssl"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Unsupported) != 1 || result.Unsupported[0].ID != "CVE-2025-0002" {
		t.Fatalf("unsupported rule was not surfaced: %+v", result)
	}
}
