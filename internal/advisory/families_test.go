package advisory

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
)

// An AlmaLinux-style patch definition: the release package checked with
// rpmverifyfile, then the package's version and signing key.
const almaOVAL = `<oval_definitions xmlns:red-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
<definitions>
 <definition id="d1" class="patch"><metadata><title>ALSA-2026:1: openssl security update (Important)</title>
  <reference ref_id="CVE-2026-0001" source="CVE" ref_url="https://access.redhat.com/security/cve/CVE-2026-0001"/>
  <reference ref_id="ALSA-2026:1" source="ALSA" ref_url="https://errata.almalinux.org/9/ALSA-2026-1.html"/>
  <advisory><severity>Important</severity></advisory></metadata>
  <criteria operator="AND">
   <criterion test_ref="t-installed" comment="AlmaLinux 9 is installed"/>
   <criteria operator="AND">
    <criterion test_ref="t-version"/>
    <criterion test_ref="t-signed"/>
   </criteria>
  </criteria>
 </definition>
 <definition id="d2" class="patch"><metadata><title>no CVEs</title></metadata><criteria><criterion test_ref="t-version"/></criteria></definition>
 <definition id="d3" class="inventory"><metadata><title>inventory</title><reference ref_id="CVE-2026-0009" source="CVE"/></metadata><criteria><criterion test_ref="t-version"/></criteria></definition>
</definitions>
<tests>
 <red-def:rpmverifyfile_test id="t-installed" check="at least one"><red-def:object object_ref="o-files"/><red-def:state state_ref="s-release"/></red-def:rpmverifyfile_test>
 <red-def:rpminfo_test id="t-version" check="at least one"><red-def:object object_ref="o-openssl"/><red-def:state state_ref="s-fixed"/></red-def:rpminfo_test>
 <red-def:rpminfo_test id="t-signed" check="at least one"><red-def:object object_ref="o-openssl"/><red-def:state state_ref="s-key"/></red-def:rpminfo_test>
</tests>
<objects>
 <red-def:rpmverifyfile_object id="o-files"><red-def:name operation="pattern match">.*</red-def:name></red-def:rpmverifyfile_object>
 <red-def:rpminfo_object id="o-openssl"><red-def:name>openssl-libs</red-def:name></red-def:rpminfo_object>
</objects>
<states>
 <red-def:rpmverifyfile_state id="s-release"><red-def:name operation="pattern match">^almalinux-release</red-def:name><red-def:version operation="pattern match">^9[^\d]</red-def:version></red-def:rpmverifyfile_state>
 <red-def:rpminfo_state id="s-fixed"><red-def:arch operation="pattern match">aarch64|x86_64</red-def:arch><red-def:evr datatype="evr_string" operation="less than">1:3.5.1-1.el9</red-def:evr></red-def:rpminfo_state>
 <red-def:rpminfo_state id="s-key"><red-def:signature_keyid operation="equals">d36cb86cb86b3716</red-def:signature_keyid></red-def:rpminfo_state>
</states>
</oval_definitions>`

func almaPackages(opensslVersion, key string) []inventory.Package {
	return []inventory.Package{
		{Name: "almalinux-release", Version: "9.8-1.el9", Arch: "aarch64", SigningKey: "d36cb86cb86b3716"},
		{Name: "openssl-libs", Version: opensslVersion, Arch: "aarch64", SigningKey: key},
	}
}

func TestFamilyOVALPatchDefinitions(t *testing.T) {
	result, err := evaluateRPMFamilyOVAL(strings.NewReader(almaOVAL), almaPackages("1:3.0.7-1.el9", "d36cb86cb86b3716"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 1 || len(result.Findings) != 1 || len(result.Unsupported) != 0 {
		t.Fatalf("result: %+v", result)
	}
	finding := result.Findings[0]
	if finding.ID != "CVE-2026-0001" || finding.Package != "openssl-libs" || finding.FixedVersion != "1:3.5.1-1.el9" || finding.Severity != "HIGH" {
		t.Fatalf("finding: %+v", finding)
	}
	// Fixed, signed by someone else (a third-party repository), or not on AlmaLinux 9.
	for name, packages := range map[string][]inventory.Package{
		"fixed":       almaPackages("1:3.5.1-1.el9", "d36cb86cb86b3716"),
		"third party": almaPackages("1:3.0.7-1.el9", "1111222233334444"),
		"almalinux 8": {{Name: "almalinux-release", Version: "8.10-1.el8", Arch: "aarch64"}, {Name: "openssl-libs", Version: "1:3.0.7-1.el9", Arch: "aarch64", SigningKey: "d36cb86cb86b3716"}},
	} {
		if result, err := evaluateRPMFamilyOVAL(strings.NewReader(almaOVAL), packages, nil); err != nil || len(result.Findings) != 0 {
			t.Errorf("%s: %+v %v", name, result.Findings, err)
		}
	}
	// An agent older than 0.19.0 doesn't report keys: assumed, and said so.
	result, _ = evaluateRPMFamilyOVAL(strings.NewReader(almaOVAL), almaPackages("1:3.0.7-1.el9", ""), nil)
	if len(result.Findings) != 1 || !result.AssumedSigned {
		t.Fatalf("without keys: %+v", result)
	}
}

// A SUSE-style CVE definition: the release package's version, then the
// package, signed with the openSUSE key; and a CVE that doesn't affect it.
const suseOVAL = `<oval_definitions><definitions>
 <definition id="s1" class="vulnerability"><metadata><title>CVE-2025-15467</title>
  <reference ref_id="Mitre CVE-2025-15467" ref_url="https://cve.mitre.org/x" source="CVE"/>
  <reference ref_id="SUSE CVE-2025-15467" ref_url="https://www.suse.com/security/cve/CVE-2025-15467" source="SUSE CVE"/>
  <advisory><severity>Critical</severity><cve href="https://www.suse.com/x">CVE-2025-15467 at SUSE</cve><cve cvss3="9.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" href="https://nvd.nist.gov/x">CVE-2025-15467 at NVD</cve></advisory></metadata>
  <criteria operator="AND"><criterion test_ref="leap"/><criteria operator="OR"><criteria operator="AND"><criterion test_ref="lt"/><criterion test_ref="key"/></criteria></criteria></criteria>
 </definition>
 <definition id="s2" class="vulnerability"><metadata><title>CVE-2017-18870</title><reference ref_id="SUSE CVE-2017-18870" source="SUSE CVE"/></metadata></definition>
</definitions><tests>
 <rpminfo_test id="leap" check="at least one"><object object_ref="o-release"/><state state_ref="s-16"/></rpminfo_test>
 <rpminfo_test id="lt" check="at least one"><object object_ref="o-ssl"/><state state_ref="s-lt"/></rpminfo_test>
 <rpminfo_test id="key" check="all"><object object_ref="o-ssl"/><state state_ref="s-key"/></rpminfo_test>
</tests><objects>
 <rpminfo_object id="o-release"><name>Leap-release</name></rpminfo_object>
 <rpminfo_object id="o-ssl"><name>libopenssl3</name></rpminfo_object>
</objects><states>
 <rpminfo_state id="s-16"><version operation="equals">16.0</version></rpminfo_state>
 <rpminfo_state id="s-lt"><arch operation="pattern match">(aarch64|x86_64)</arch><evr operation="less than">0:3.5.0-160000.5.1</evr></rpminfo_state>
 <rpminfo_state id="s-key"><signature_keyid operation="equals">b88b2fd43dbdc284</signature_keyid></rpminfo_state>
</states></oval_definitions>`

func TestSUSEVendorKeysAndBuildMetadata(t *testing.T) {
	packages := []inventory.Package{
		// Leap 16's release package is 16.0+leap; its packages are signed
		// with the SUSE 16 key, not the openSUSE key the feed names.
		{Name: "Leap-release", Version: "16.0+leap-lp160.264.1", Arch: "aarch64"},
		{Name: "libopenssl3", Version: "3.0.1-1.1", Arch: "aarch64", SigningKey: "fec28eaf09d9ea69"},
	}
	result, err := evaluateRPMFamilyOVAL(strings.NewReader(suseOVAL), packages, VendorKeys["suse"])
	if err != nil || len(result.Findings) != 1 || result.Evaluated != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	finding := result.Findings[0]
	if finding.ID != "CVE-2025-15467" || finding.FixedVersion != "3.5.0-160000.5.1" || finding.Severity != "CRITICAL" ||
		finding.CVSSScore != 9.8 || finding.URL != "https://www.suse.com/security/cve/CVE-2025-15467" {
		t.Fatalf("finding: %+v", finding)
	}
	// Without the vendor keys, a SUSE-signed package is not openSUSE's.
	if result, _ := evaluateRPMFamilyOVAL(strings.NewReader(suseOVAL), packages, nil); len(result.Findings) != 0 {
		t.Fatalf("without vendor keys: %+v", result.Findings)
	}
}

const rockyUpdateInfo = `<updates>
 <update type="security"><id>RLSA-2022:7288</id><title>Important: openssl security update</title><severity>Important</severity>
  <references><reference id="CVE-2022-3602" type="cve" href="x"/><reference id="CVE-2022-3786" type="cve"/></references>
  <pkglist><collection><package name="openssl-libs" epoch="1" version="3.0.1" release="43.el9_0" arch="aarch64"/><package name="openssl-libs" epoch="1" version="3.0.1" release="43.el9_0" arch="x86_64"/><package name="openssl" epoch="1" version="3.0.1" release="43.el9_0" arch="src"/></collection></pkglist></update>
 <update type="security"><id>RLSA-2023:1</id><title>Later openssl update</title><severity>Moderate</severity>
  <references><reference id="CVE-2022-3602" type="cve"/></references>
  <pkglist><collection><package name="openssl-libs" epoch="1" version="3.0.7" release="1.el9" arch="aarch64"/></collection></pkglist></update>
 <update type="bugfix"><id>RLBA-2023:2</id><references><reference id="CVE-2099-0001" type="cve"/></references><pkglist><collection><package name="openssl-libs" version="9" release="1" arch="aarch64"/></collection></pkglist></update>
</updates>`

const fedoraUpdateInfo = `<updates><update type="security"><id>FEDORA-2026-abc</id><title>curl-8.15.0-3.fc44</title><severity>Important</severity>
 <references><reference type="bugzilla" id="2400001" title="CVE-2026-1111 curl: use after free [fedora-44]"/></references>
 <pkglist><collection><package name="libcurl" version="8.15.0" release="3.fc44" epoch="0" arch="aarch64"/></collection></pkglist></update></updates>`

func TestUpdateInfo(t *testing.T) {
	packages := []inventory.Package{{Name: "openssl-libs", Version: "1:3.0.1-1.el9", Arch: "aarch64"}, {Name: "libcurl", Version: "8.15.0-1.fc44", Arch: "aarch64"}}
	result, err := evaluateUpdateInfo([]UpdateInfoSource{
		{Data: strings.NewReader(rockyUpdateInfo), Advisory: func(id string) string { return "https://errata.rockylinux.org/" + id }},
		{Data: strings.NewReader(fedoraUpdateInfo)},
	}, packages)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Finding{}
	for _, finding := range result.Findings {
		got[finding.ID] = finding
	}
	// The earliest version that fixes CVE-2022-3602, from its first advisory.
	if f := got["CVE-2022-3602"]; f.FixedVersion != "1:3.0.1-43.el9_0" || f.Severity != "HIGH" || f.URL != "https://errata.rockylinux.org/RLSA-2022:7288" {
		t.Fatalf("CVE-2022-3602: %+v", f)
	}
	if _, found := got["CVE-2099-0001"]; found {
		t.Fatal("a bug fix update counted")
	}
	// Fedora names its CVEs in Bugzilla titles.
	if f := got["CVE-2026-1111"]; f.Package != "libcurl" || f.FixedVersion != "8.15.0-3.fc44" {
		t.Fatalf("fedora: %+v", got)
	}
	if len(result.Findings) != 3 || result.Evaluated != 3 {
		t.Fatalf("findings: %+v, evaluated %d", result.Findings, result.Evaluated)
	}
}

func TestDecompressAndLocate(t *testing.T) {
	var gz, zs bytes.Buffer
	writer := gzip.NewWriter(&gz)
	writer.Write([]byte("<x/>"))
	writer.Close()
	encoder, _ := zstd.NewWriter(&zs)
	encoder.Write([]byte("<y/>"))
	encoder.Close()
	for _, data := range [][]byte{gz.Bytes(), zs.Bytes(), []byte("<?xml version='1.0'?><z/>")} {
		if _, err := decompress(data); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := decompress([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
	repomd := []byte(`<repomd><data type="primary"><location href="repodata/p.xml.gz"/></data><data type="updateinfo"><location href="repodata/u-updateinfo.xml.zst"/></data></repomd>`)
	if location, err := updateInfoLocation(repomd); err != nil || location != "repodata/u-updateinfo.xml.zst" {
		t.Fatalf("%q %v", location, err)
	}
	if _, err := updateInfoLocation([]byte(`<repomd><data type="updateinfo"><location href="../../etc/passwd"/></data></repomd>`)); err == nil {
		t.Fatal("a location leaving the repository was accepted")
	}
	if arch := Architecture([]inventory.Package{{Name: "bash", Arch: "x86_64"}, {Name: "glibc", Arch: "aarch64"}}); arch != "aarch64" {
		t.Fatalf("arch: %s", arch)
	}
}

func TestFeedSources(t *testing.T) {
	for _, test := range []struct {
		target platform.Platform
		url    string
	}{
		{platform.Platform{Family: platform.Alma, Major: 9}, "https://security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2"},
		{platform.Platform{Family: platform.Oracle, Major: 10}, "https://linux.oracle.com/security/oval/com.oracle.elsa-ol10.xml.bz2"},
		{platform.Platform{Family: platform.OpenSUSELeap, VersionID: "16.0", Major: 16}, "https://ftp.suse.com/pub/projects/security/oval/opensuse.leap.16.0.xml.gz"},
		{platform.Platform{Family: platform.SLES, VersionID: "15.7", Major: 15, Minor: 7}, "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.15-sp7.xml.gz"},
		{platform.Platform{Family: platform.SLES, VersionID: "16.0", Major: 16}, "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.16.0.xml.gz"},
	} {
		if url, _, err := FamilyOVALSource(test.target); err != nil || url != test.url {
			t.Errorf("%+v: %s %v", test.target, url, err)
		}
	}
}
