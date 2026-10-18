// Package sbom writes a software bill of materials for a scan: every
// installed OS package and every application library it found, as CycloneDX
// 1.6 or SPDX 2.3 JSON, each identified by a package URL (purl).
package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
)

// Formats.
const (
	CycloneDX = "cyclonedx"
	SPDX      = "spdx"
)

// ErrNoInventory is returned for a scan that recorded no packages or
// libraries, such as one from before 1.1.0.
var ErrNoInventory = errors.New("this scan has no package list for an SBOM: run a new scan (DeaconGuard 1.1.0 or later) with package vulnerabilities or application libraries")

type component struct {
	name, version, purl, kind, group string
}

type scanReport struct {
	ID        string `json:"report_id"`
	Address   string `json:"address"`
	OS        string `json:"os"`
	ScannedAt string `json:"scanned_at"`
	Distro    struct {
		ID        string `json:"id"`
		VersionID string `json:"version_id"`
	} `json:"distro"`
	PackageManager string `json:"package_manager"`
	Packages       []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Arch    string `json:"arch"`
	} `json:"installed_packages"`
	CheckResults map[string]struct {
		Libraries *struct {
			Libraries []struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
				Version   string `json:"version"`
			} `json:"libraries"`
		} `json:"libraries"`
	} `json:"check_results"`
}

// Build writes the SBOM of a full scan report (store.GetFullReport) in
// format, and returns a file name for it.
func Build(report map[string]any, format string) ([]byte, string, error) {
	if format != CycloneDX && format != SPDX {
		return nil, "", fmt.Errorf("unknown SBOM format %q: use %s or %s", format, CycloneDX, SPDX)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, "", err
	}
	var scan scanReport
	if err := json.Unmarshal(encoded, &scan); err != nil {
		return nil, "", fmt.Errorf("read scan report: %w", err)
	}
	components := collect(scan)
	if len(components) == 0 {
		return nil, "", ErrNoInventory
	}
	scanned, err := time.Parse(time.RFC3339, scan.ScannedAt)
	if err != nil {
		scanned = time.Now().UTC()
	}
	base := fmt.Sprintf("deaconguard-%s-%s", fileSafe(scan.Address), scanned.UTC().Format("20060102-150405"))
	var document any
	var name string
	if format == CycloneDX {
		document, name = cycloneDX(scan, components, scanned), base+".cdx.json"
	} else {
		document, name = spdx(scan, components, scanned), base+".spdx.json"
	}
	// Package URLs keep & and < as they are, rather than as \u0026 and \u003c.
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil, "", err
	}
	return out.Bytes(), name, nil
}

func collect(scan scanReport) []component {
	var components []component
	seen := make(map[string]bool)
	add := func(c component) {
		if c.name == "" || c.version == "" || seen[c.purl] {
			return
		}
		seen[c.purl] = true
		components = append(components, c)
	}
	for _, p := range scan.Packages {
		add(component{name: p.Name, version: p.Version, purl: osPURL(scan, p.Name, p.Version, p.Arch), kind: "os"})
	}
	if result, ok := scan.CheckResults["libraries"]; ok && result.Libraries != nil {
		for _, l := range result.Libraries.Libraries {
			purl, group, name := libraryPURL(l.Ecosystem, l.Name, l.Version)
			if purl != "" {
				add(component{name: name, group: group, version: l.Version, purl: purl, kind: "library"})
			}
		}
	}
	sort.SliceStable(components, func(i, j int) bool {
		if components[i].kind != components[j].kind {
			return components[i].kind == "os"
		}
		return components[i].purl < components[j].purl
	})
	return components
}

// osPURL is a deb or rpm package URL. An RPM version "1:3.0.7-25.el9" puts
// the epoch in a qualifier, as the purl specification asks.
func osPURL(scan scanReport, name, version, arch string) string {
	kind := "deb"
	if scan.PackageManager == "rpm" {
		kind = "rpm"
	}
	namespace := scan.Distro.ID
	if namespace == "" {
		namespace = "linux"
	}
	qualifiers := url.Values{}
	if arch != "" {
		qualifiers.Set("arch", arch)
	}
	if kind == "rpm" {
		if epoch, rest, found := strings.Cut(version, ":"); found {
			qualifiers.Set("epoch", epoch)
			version = rest
		}
	}
	if scan.Distro.ID != "" && scan.Distro.VersionID != "" {
		qualifiers.Set("distro", scan.Distro.ID+"-"+scan.Distro.VersionID)
	}
	purl := fmt.Sprintf("pkg:%s/%s/%s@%s", kind, escape(namespace), escape(name), escape(version))
	if encoded := qualifiers.Encode(); encoded != "" {
		purl += "?" + encoded
	}
	return purl
}

// libraryPURL is a library's package URL, with its group (namespace) and
// name as SBOM tools expect them.
func libraryPURL(ecosystem, name, version string) (purl, group, short string) {
	types := map[string]string{"npm": "npm", "PyPI": "pypi", "Go": "golang", "RubyGems": "gem", "crates.io": "cargo", "Packagist": "composer"}
	kind, ok := types[ecosystem]
	if !ok {
		return "", "", ""
	}
	short = name
	if kind == "npm" || kind == "golang" || kind == "composer" {
		if index := strings.LastIndex(name, "/"); index > 0 {
			group, short = name[:index], name[index+1:]
		}
	}
	path := escape(short)
	if group != "" {
		segments := strings.Split(group, "/")
		for index, segment := range segments {
			segments[index] = escape(segment)
		}
		path = strings.Join(segments, "/") + "/" + path
	}
	return fmt.Sprintf("pkg:%s/%s@%s", kind, path, escape(version)), group, short
}

// escape percent-encodes a purl segment, keeping the characters the purl
// specification leaves as they are.
func escape(segment string) string {
	return strings.NewReplacer("+", "%2B", "@", "%40", ":", "%3A").Replace(url.PathEscape(segment))
}

var unsafeFile = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func fileSafe(value string) string {
	value = strings.Trim(unsafeFile.ReplaceAllString(value, "-"), "-")
	if value == "" {
		return "host"
	}
	return value
}

// uuidFrom makes a stable UUID (version 5 style) from text, so the same scan
// always gets the same serial number.
func uuidFrom(text string) string {
	sum := sha256.Sum256([]byte("deaconguard-sbom:" + text))
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func cycloneDX(scan scanReport, components []component, scanned time.Time) map[string]any {
	list := make([]map[string]any, 0, len(components))
	for _, c := range components {
		entry := map[string]any{"type": "library", "bom-ref": c.purl, "name": c.name, "version": c.version, "purl": c.purl}
		if c.group != "" {
			entry["group"] = c.group
		}
		if c.kind == "os" {
			entry["properties"] = []map[string]string{{"name": "deaconguard:source", "value": "os-package"}}
		}
		list = append(list, entry)
	}
	return map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + uuidFrom(scan.ID),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": scanned.UTC().Format(time.RFC3339),
			"tools": map[string]any{"components": []map[string]any{{
				"type": "application", "name": "DeaconGuard", "version": buildinfo.Version,
				"externalReferences": []map[string]string{{"type": "website", "url": "https://deaconguard.io"}},
			}}},
			"component": map[string]any{"type": "operating-system", "bom-ref": "host", "name": scan.Address, "description": scan.OS},
		},
		"components": list,
	}
}

func spdx(scan scanReport, components []component, scanned time.Time) map[string]any {
	packages := make([]map[string]any, 0, len(components))
	relationships := make([]map[string]string, 0, len(components))
	for index, c := range components {
		id := fmt.Sprintf("SPDXRef-Package-%d", index+1)
		name := c.name
		if c.group != "" {
			name = c.group + "/" + c.name
		}
		packages = append(packages, map[string]any{
			"name": name, "SPDXID": id, "versionInfo": c.version,
			"downloadLocation": "NOASSERTION", "filesAnalyzed": false,
			"licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
			"externalRefs": []map[string]string{{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.purl}},
		})
		relationships = append(relationships, map[string]string{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": id})
	}
	return map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              fmt.Sprintf("%s (%s)", scan.Address, scan.OS),
		"documentNamespace": "https://deaconguard.io/spdx/" + uuidFrom(scan.ID),
		"creationInfo": map[string]any{
			"created":  scanned.UTC().Format(time.RFC3339),
			"creators": []string{"Tool: DeaconGuard-" + buildinfo.Version},
		},
		"packages":      packages,
		"relationships": relationships,
	}
}
