package sbom

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func report(manager, distro, version string, packages []map[string]any) map[string]any {
	return map[string]any{
		"report_id": "abc123", "address": "web-01", "os": "Rocky Linux 9.3", "scanned_at": "2026-10-18T10:00:00Z",
		"distro": map[string]any{"id": distro, "version_id": version}, "package_manager": manager,
		"installed_packages": packages,
		"check_results": map[string]any{"libraries": map[string]any{"libraries": map[string]any{"libraries": []any{
			map[string]any{"ecosystem": "npm", "name": "@babel/core", "version": "7.22.0"},
			map[string]any{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
			map[string]any{"ecosystem": "PyPI", "name": "requests", "version": "2.25.1"},
			map[string]any{"ecosystem": "Go", "name": "github.com/gin-gonic/gin", "version": "v1.7.0"},
			map[string]any{"ecosystem": "Packagist", "name": "guzzlehttp/guzzle", "version": "7.4.0"},
			map[string]any{"ecosystem": "RubyGems", "name": "rack", "version": "2.2.3"},
			map[string]any{"ecosystem": "crates.io", "name": "time", "version": "0.1.43"},
		}}}},
	}
}

func TestCycloneDX(t *testing.T) {
	out, name, err := Build(report("rpm", "rocky", "9.3", []map[string]any{
		{"name": "openssl", "version": "1:3.0.7-25.el9", "arch": "x86_64"},
		{"name": "c++-libs", "version": "1.0-1.el9", "arch": "noarch"},
		{"name": "deb-style", "version": "2:1.0", "arch": ""},
	}), CycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	if name != "deaconguard-web-01-20261018-100000.cdx.json" {
		t.Errorf("name = %s", name)
	}
	var bom struct {
		BOMFormat, SpecVersion, SerialNumber string
		Components                           []struct{ Name, Group, Version, Purl string }
	}
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `\u0026`) {
		t.Error("purls should keep & unescaped")
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("header = %+v", bom)
	}
	purls := make(map[string]bool)
	for _, c := range bom.Components {
		purls[c.Purl] = true
	}
	for _, want := range []string{
		"pkg:rpm/rocky/openssl@3.0.7-25.el9?arch=x86_64&distro=rocky-9.3&epoch=1",
		"pkg:rpm/rocky/c%2B%2B-libs@1.0-1.el9?arch=noarch&distro=rocky-9.3",
		"pkg:npm/%40babel/core@7.22.0",
		"pkg:npm/lodash@4.17.20",
		"pkg:pypi/requests@2.25.1",
		"pkg:golang/github.com/gin-gonic/gin@v1.7.0",
		"pkg:composer/guzzlehttp/guzzle@7.4.0",
		"pkg:gem/rack@2.2.3",
		"pkg:cargo/time@0.1.43",
		"pkg:rpm/rocky/deb-style@1.0?distro=rocky-9.3&epoch=2",
	} {
		if !purls[want] {
			t.Errorf("missing %s in %v", want, purls)
		}
	}
	if len(bom.Components) != 10 || bom.Components[0].Purl[:8] != "pkg:rpm/" {
		t.Errorf("components = %d, OS packages first: %+v", len(bom.Components), bom.Components)
	}
	again, _, _ := Build(report("rpm", "rocky", "9.3", []map[string]any{{"name": "openssl", "version": "1:3.0.7-25.el9", "arch": "x86_64"}}), CycloneDX)
	var second struct{ SerialNumber string }
	json.Unmarshal(again, &second)
	if second.SerialNumber != bom.SerialNumber {
		t.Error("the same scan should keep its serial number")
	}
}

func TestSPDX(t *testing.T) {
	out, name, err := Build(report("dpkg", "ubuntu", "24.04", []map[string]any{{"name": "openssl", "version": "3.0.13-0ubuntu3.4", "arch": "amd64"}}), SPDX)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".spdx.json") {
		t.Errorf("name = %s", name)
	}
	var doc struct {
		SPDXVersion, DataLicense, SPDXID string
		Packages                         []struct {
			Name, SPDXID, VersionInfo string
			ExternalRefs              []struct{ ReferenceType, ReferenceLocator string }
		}
		Relationships []struct{ RelationshipType string }
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("header = %+v", doc)
	}
	if len(doc.Packages) != 8 || len(doc.Relationships) != 8 {
		t.Fatalf("packages = %d, relationships = %d", len(doc.Packages), len(doc.Relationships))
	}
	first := doc.Packages[0]
	if first.Name != "openssl" || first.ExternalRefs[0].ReferenceLocator != "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04" {
		t.Errorf("first package = %+v", first)
	}
	found := false
	for _, p := range doc.Packages {
		found = found || p.Name == "@babel/core"
	}
	if !found {
		t.Error("scoped npm package should keep its full name in SPDX")
	}
}

func TestNoInventory(t *testing.T) {
	if _, _, err := Build(map[string]any{"address": "old", "scanned_at": "2026-01-01T00:00:00Z"}, CycloneDX); !errors.Is(err, ErrNoInventory) {
		t.Errorf("err = %v, want ErrNoInventory", err)
	}
	if _, _, err := Build(map[string]any{}, "xml"); err == nil {
		t.Error("unknown format accepted")
	}
}
