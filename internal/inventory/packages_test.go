package inventory

import "testing"

func TestParseDPKGStatus(t *testing.T) {
	contents := "Package: libexample1\nStatus: install ok installed\nVersion: 2:1.4-3ubuntu1\nSource: example (1.4-3)\n\n" +
		"Package: not-installed\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
	packages, err := ParseDPKGStatus(contents)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0] != (Package{
		Name: "libexample1", Version: "2:1.4-3ubuntu1", Source: "example",
	}) {
		t.Fatalf("ParseDPKGStatus() = %#v", packages)
	}
}

func TestParseRPMQuery(t *testing.T) {
	contents := "openssl-libs\t1\t3.2.2\t6.amzn2023.0.1\topenssl-3.2.2-6.amzn2023.0.1.src.rpm\tx86_64\n" +
		"bash\t(none)\t5.2.26\t1.amzn2023.0.2\tbash-5.2.26-1.amzn2023.0.2.src.rpm\taarch64\n"
	packages, err := ParseRPMQuery(contents)
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("got %d packages, want 2", len(packages))
	}
	if packages[0].Version != "1:3.2.2-6.amzn2023.0.1" || packages[0].Source != "openssl" || packages[0].Arch != "x86_64" {
		t.Fatalf("unexpected RPM package: %+v", packages[0])
	}
	if packages[1].Version != "5.2.26-1.amzn2023.0.2" {
		t.Fatalf("unexpected RPM epoch handling: %+v", packages[1])
	}
}

func TestRejectsMalformedRPMInventory(t *testing.T) {
	if _, err := ParseRPMQuery("broken row"); err == nil {
		t.Fatal("expected malformed RPM row to fail")
	}
}
