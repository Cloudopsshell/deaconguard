package advisory

import (
	"testing"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
)

func TestEvaluateDebianUsesSourcePackageAndBookwormFixVersion(t *testing.T) {
	target := platform.Platform{Family: platform.Debian, VersionID: "12", Codename: "bookworm"}
	packages := []inventory.Package{
		{Name: "libexample1", Version: "1.4-1", Source: "example"},
		{Name: "example-data", Version: "1.4-1", Source: "example"},
		{Name: "unrelated", Version: "2.0-1", Source: "unrelated"},
	}
	tracker := []byte(`{"example":{"CVE-2025-0001":{"description":"Example issue","releases":{"bookworm":{"status":"resolved","fixed_version":"1.4-2","urgency":"high"}}}}}`)
	result, err := EvaluateDebian(target, packages, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 2 || len(result.Findings) != 2 {
		t.Fatalf("unexpected evaluation: %+v", result)
	}
	if result.Findings[0].Severity != "HIGH" || result.Findings[0].FixedVersion != "1.4-2" {
		t.Fatalf("unexpected finding: %+v", result.Findings[0])
	}
}

func TestEvaluateDebianDoesNotMarkUnknownTrackerStatesClean(t *testing.T) {
	target := platform.Platform{Family: platform.Debian, VersionID: "13", Codename: "trixie"}
	packages := []inventory.Package{{Name: "example", Version: "1.0-1", Source: "example"}}
	tracker := []byte(`{"example":{"CVE-2025-0002":{"description":"Untriaged issue","releases":{"trixie":{"status":"undetermined","urgency":"not yet assigned"}}}}}`)
	result, err := EvaluateDebian(target, packages, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Unsupported) != 1 || result.Unsupported[0].ID != "CVE-2025-0002" {
		t.Fatalf("unknown issue status was not surfaced: %+v", result)
	}
}

func TestEvaluateDebianCountsResolvedWithoutFixedVersion(t *testing.T) {
	target := platform.Platform{Family: platform.Debian, VersionID: "12", Codename: "bookworm"}
	packages := []inventory.Package{{Name: "example", Version: "1.0-1", Source: "example"}}
	tracker := []byte(`{"example":{"CVE-2025-0003":{"description":"Resolved without a version comparison","releases":{"bookworm":{"status":"resolved","fixed_version":"0","urgency":"unimportant"}}}}}`)
	result, err := EvaluateDebian(target, packages, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 1 || len(result.Findings) != 0 {
		t.Fatalf("resolved non-versioned status was not accounted for: %+v", result)
	}
}
