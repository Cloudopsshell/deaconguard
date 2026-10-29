package advisory

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"

	"deaconguard/internal/inventory"
	"deaconguard/internal/version"
)

// updateinfo is the errata metadata RPM repositories publish next to their
// packages (repodata/*-updateinfo.xml), which dnf reads for
// "dnf updateinfo". Rocky Linux and Fedora publish their security advisories
// this way: each security update names its CVEs and the package versions
// that fix them.

type updateInfo struct {
	Type       string `xml:"type,attr"`
	ID         string `xml:"id"`
	Title      string `xml:"title"`
	Severity   string `xml:"severity"`
	References []struct {
		Href  string `xml:"href,attr"`
		ID    string `xml:"id,attr"`
		Type  string `xml:"type,attr"`
		Title string `xml:"title,attr"`
	} `xml:"references>reference"`
	Packages []struct {
		Name    string `xml:"name,attr"`
		Epoch   string `xml:"epoch,attr"`
		Version string `xml:"version,attr"`
		Release string `xml:"release,attr"`
		Arch    string `xml:"arch,attr"`
	} `xml:"pkglist>collection>package"`
}

// UpdateInfoSource is one repository's updateinfo, decompressed, with a
// link to its advisories, such as https://errata.rockylinux.org/.
type UpdateInfoSource struct {
	Data     io.Reader
	Advisory func(id string) string
	// updates are Data's security updates, when already parsed.
	updates []securityUpdate
}

// securityUpdate is a security update from updateinfo, with its CVEs.
type securityUpdate struct {
	update updateInfo
	cves   []string
}

// parseUpdateInfo reads the security updates that name CVEs from an
// updateinfo stream.
func parseUpdateInfo(stream io.Reader) ([]securityUpdate, error) {
	updates := make([]securityUpdate, 0, 1024)
	decoder := xml.NewDecoder(stream)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return updates, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read updateinfo: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "update" {
			continue
		}
		var update updateInfo
		if err := decoder.DecodeElement(&update, &start); err != nil {
			return nil, fmt.Errorf("read an update: %w", err)
		}
		if update.Type != "security" {
			continue
		}
		if cves := updateCVEs(update); len(cves) > 0 {
			updates = append(updates, securityUpdate{update: update, cves: cves})
		}
	}
}

// evaluateUpdateInfo finds the installed packages older than a security
// update that fixes them, in one or more repositories' updateinfo. Each CVE
// is reported once per package, with the earliest version that fixes it.
func evaluateUpdateInfo(sources []UpdateInfoSource, packages []inventory.Package) (DebianEvaluation, error) {
	installed := make(map[string][]inventory.Package)
	for _, item := range packages {
		installed[item.Name] = append(installed[item.Name], item)
	}
	type key struct{ cve, name, installed string }
	best := make(map[key]Finding)
	result := DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}
	for _, source := range sources {
		updates := source.updates
		if updates == nil {
			var err error
			if updates, err = parseUpdateInfo(source.Data); err != nil {
				return DebianEvaluation{}, err
			}
		}
		for _, parsed := range updates {
			update, cves := parsed.update, parsed.cves
			result.Evaluated++
			link := ""
			if source.Advisory != nil {
				link = source.Advisory(update.ID)
			}
			for _, fixed := range update.Packages {
				for _, item := range installed[fixed.Name] {
					if fixed.Arch != "" && fixed.Arch != "noarch" && fixed.Arch != "src" && item.Arch != "" && item.Arch != fixed.Arch {
						continue
					}
					if fixed.Arch == "src" {
						continue
					}
					target := fixed.Version + "-" + fixed.Release
					if fixed.Epoch != "" && fixed.Epoch != "0" {
						target = fixed.Epoch + ":" + target
					}
					older, err := version.RPM(item.Version, target)
					if err != nil || older >= 0 {
						continue
					}
					for _, cve := range cves {
						index := key{cve, item.Name, item.Version}
						if current, seen := best[index]; seen {
							if earlier, err := version.RPM(target, current.FixedVersion); err != nil || earlier >= 0 {
								continue
							}
						}
						best[index] = Finding{ID: cve, Package: item.Name, InstalledVersion: item.Version, FixedVersion: target,
							Severity: normalizeSeverity(update.Severity), URL: link, Title: update.ID + ": " + update.Title}
					}
				}
			}
		}
	}
	for _, finding := range best {
		result.Findings = append(result.Findings, finding)
	}
	sort.Slice(result.Findings, func(a, b int) bool {
		left, right := result.Findings[a], result.Findings[b]
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return left.Package < right.Package
	})
	return result, nil
}

// updateCVEs are an update's CVEs: its cve references, and, for Fedora,
// whose references are Bugzilla bugs, the CVEs those bugs' titles name.
func updateCVEs(update updateInfo) []string {
	seen := make(map[string]bool)
	cves := make([]string, 0)
	for _, reference := range update.References {
		candidates := []string{reference.ID}
		if reference.Type != "cve" {
			candidates = familyCVE.FindAllString(reference.Title, -1)
		}
		for _, candidate := range candidates {
			if id := familyCVE.FindString(candidate); id != "" && !seen[id] {
				seen[id] = true
				cves = append(cves, id)
			}
		}
	}
	return cves
}
