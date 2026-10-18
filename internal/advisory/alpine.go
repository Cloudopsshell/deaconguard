package advisory

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
	"deaconguard/internal/version"
)

// Alpine's security database lists, for each source package (origin) of a
// branch's main and community repositories, the versions that fixed which
// CVEs. It lists fixes only: a vulnerability Alpine hasn't fixed yet isn't in
// it. Severities come from elsewhere (see the scanner).
const alpineSecDBBase = "https://secdb.alpinelinux.org/"

type alpineSecDB struct {
	Packages []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// LoadAlpineSecDB loads the main and community security databases of the
// target's branch, cached like the other feeds. The two are returned joined
// as one JSON array.
func LoadAlpineSecDB(target platform.Platform, client HTTPClient, now time.Time) (Feed, error) {
	if target.Family != platform.Alpine {
		return Feed{}, fmt.Errorf("Alpine's security database cannot evaluate %s", target.Family)
	}
	var parts []json.RawMessage
	var metadata FeedMetadata
	for _, repository := range []string{"main", "community"} {
		source := fmt.Sprintf("%s%s/%s.json", alpineSecDBBase, target.Codename, repository)
		feed, err := LoadFeed(source, fmt.Sprintf("alpine-%s-%s", strings.TrimPrefix(target.Codename, "v"), repository), client, now)
		if err != nil {
			return Feed{}, err
		}
		parts = append(parts, json.RawMessage(feed.Data))
		if repository == "main" {
			metadata = feed.Metadata
			metadata.Source = alpineSecDBBase + target.Codename + "/ (main and community)"
		} else if feed.Metadata.Stale {
			metadata.Stale, metadata.RefreshError = true, feed.Metadata.RefreshError
		}
	}
	joined, err := json.Marshal(parts)
	if err != nil {
		return Feed{}, err
	}
	return Feed{Metadata: metadata, Data: joined}, nil
}

// EvaluateAlpine reports each CVE that a newer version of an installed
// package fixes. secfixes entries under version "0" are CVEs Alpine says
// never affected it, and are skipped.
func EvaluateAlpine(target platform.Platform, packages []inventory.Package, feedJSON []byte) (DebianEvaluation, error) {
	var databases []alpineSecDB
	if err := json.Unmarshal(feedJSON, &databases); err != nil {
		return DebianEvaluation{}, fmt.Errorf("parse Alpine's security database: %w", err)
	}
	fixes := make(map[string]map[string][]string) // origin -> fixed version -> CVEs
	for _, database := range databases {
		for _, entry := range database.Packages {
			if fixes[entry.Pkg.Name] == nil {
				fixes[entry.Pkg.Name] = make(map[string][]string)
			}
			for fixed, ids := range entry.Pkg.Secfixes {
				fixes[entry.Pkg.Name][fixed] = append(fixes[entry.Pkg.Name][fixed], ids...)
			}
		}
	}
	if len(fixes) == 0 {
		return DebianEvaluation{}, fmt.Errorf("Alpine's security database for %s is empty", target.Codename)
	}

	result := DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}
	for _, installed := range packages {
		// The lowest fixing version newer than the installed one, per CVE.
		lowest := make(map[string]string)
		for fixed, ids := range fixes[installed.Source] {
			if fixed == "0" {
				continue
			}
			newer, err := version.APK(installed.Version, fixed)
			if err != nil || newer >= 0 {
				continue
			}
			for _, line := range ids {
				// Most entries are one CVE; some name several, or another
				// advisory such as Xen's XSA-248, which is reported as well.
				for _, id := range strings.Fields(line) {
					if current, seen := lowest[id]; seen {
						if order, err := version.APK(fixed, current); err == nil && order >= 0 {
							continue
						}
					}
					lowest[id] = fixed
				}
			}
		}
		for id, fixed := range lowest {
			result.Findings = append(result.Findings, Finding{
				ID: id, Package: installed.Name, InstalledVersion: installed.Version, FixedVersion: fixed,
				Severity: "UNKNOWN", URL: "https://security.alpinelinux.org/vuln/" + id, Title: id,
			})
		}
		result.Evaluated++
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Package != result.Findings[j].Package {
			return result.Findings[i].Package < result.Findings[j].Package
		}
		return result.Findings[i].ID < result.Findings[j].ID
	})
	return result, nil
}
