package advisory

import (
	"testing"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
)

func TestEvaluateAlpine(t *testing.T) {
	feed := []byte(`[
		{"packages":[{"pkg":{"name":"openssl","secfixes":{
			"3.1.4-r1":["CVE-2023-5678"],
			"3.1.4-r5":["CVE-2024-0727 CVE-2024-0728"],
			"3.3.2-r0":["CVE-2024-6119"],
			"0":["CVE-2022-0001"]}}}]},
		{"packages":[{"pkg":{"name":"xen","secfixes":{"4.18.0-r1":["XSA-248"]}}}]}
	]`)
	packages := []inventory.Package{
		{Name: "libcrypto3", Version: "3.1.4-r1", Source: "openssl"},
		{Name: "xen", Version: "4.18.0-r0", Source: "xen"},
		{Name: "busybox", Version: "1.36.1-r0", Source: "busybox"},
	}
	result, err := EvaluateAlpine(platform.Platform{Family: platform.Alpine, Codename: "v3.19"}, packages, feed)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range result.Findings {
		got[f.Package+" "+f.ID] = f.FixedVersion
	}
	want := map[string]string{
		"libcrypto3 CVE-2024-0727": "3.1.4-r5", "libcrypto3 CVE-2024-0728": "3.1.4-r5",
		"libcrypto3 CVE-2024-6119": "3.3.2-r0", "xen XSA-248": "4.18.0-r1",
	}
	if len(got) != len(want) {
		t.Errorf("findings = %v, want %v (3.1.4-r1 already has CVE-2023-5678's fix; version 0 never affected Alpine)", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s fixed in %q, want %q", k, got[k], v)
		}
	}
	if result.Evaluated != 3 {
		t.Errorf("evaluated %d packages, want 3", result.Evaluated)
	}
}

func TestEvaluateAlpineEmpty(t *testing.T) {
	if _, err := EvaluateAlpine(platform.Platform{Family: platform.Alpine}, nil, []byte(`[{"packages":[]}]`)); err == nil {
		t.Error("an empty database must be an error, never a clean result")
	}
}
