package store

import (
	"database/sql"
	"sort"
	"strings"
)

// A cluster's nodes, made from one image, mostly have the same findings.
// The cluster's page and the dashboard show each finding once, with the
// nodes it's on, rather than once per node.

// NodeVersion is one node a combined finding is on, with what it has.
type NodeVersion struct {
	HostID           string `json:"host_id"`
	Host             string `json:"host"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	Fix              string `json:"fix,omitempty"`
}

// ClusterVulnerability is one vulnerable package on a cluster's nodes, once.
type ClusterVulnerability struct {
	CVE       string   `json:"cve"`
	Package   string   `json:"package"`
	Severity  string   `json:"severity"`
	Title     string   `json:"title"`
	URL       string   `json:"url"`
	Priority  string   `json:"priority"`
	KEV       bool     `json:"kev"`
	EPSS      *float64 `json:"epss,omitempty"`
	CVSSScore float64  `json:"cvss_score,omitempty"`
	// Fix is the most a node can do about it: an update, a restart, or
	// what's in the way.
	Fix          string        `json:"fix"`
	FixedVersion string        `json:"fixed_version,omitempty"`
	Nodes        []NodeVersion `json:"nodes"`
}

// ClusterCheckFinding is one finding of another check on a cluster's
// nodes, once: the same rule about the same thing.
type ClusterCheckFinding struct {
	Rule     string        `json:"rule"`
	Severity string        `json:"severity"`
	Title    string        `json:"title"`
	Detail   string        `json:"detail"`
	Evidence string        `json:"evidence"`
	Nodes    []NodeVersion `json:"nodes"`
}

// ClusterFindings is a check's combined findings on a cluster's nodes.
type ClusterFindings struct {
	Check string `json:"check"`
	// Nodes counts the cluster's nodes; Checked those with a result of the
	// check, Excluded those left out of its scans.
	Nodes    int `json:"nodes"`
	Checked  int `json:"checked"`
	Excluded int `json:"excluded"`
	// Vulnerabilities, for the packages check; Findings for the others.
	Vulnerabilities []ClusterVulnerability `json:"vulnerabilities,omitempty"`
	Findings        []ClusterCheckFinding  `json:"findings,omitempty"`
	// Counts are the combined findings by severity.
	Counts SeverityCounts `json:"counts"`
}

// fixOrder ranks fix states, most actionable first.
var fixOrder = map[string]int{"available": 5, "reboot": 4, "ubuntu_pro": 3, "old_kernel": 2, "none": 1}

// combineVulnerabilities groups node findings by CVE and package.
func combineVulnerabilities(affected []AffectedPackage, cves []string) []ClusterVulnerability {
	byKey := map[string]*ClusterVulnerability{}
	var order []string
	for index, item := range affected {
		key := cves[index] + "\x00" + item.Package
		combined, ok := byKey[key]
		if !ok {
			combined = &ClusterVulnerability{CVE: cves[index], Package: item.Package, Severity: item.Severity, Title: item.Title, URL: item.URL,
				Priority: item.Priority, Fix: item.Fix, FixedVersion: item.FixedVersion}
			byKey[key] = combined
			order = append(order, key)
		}
		if severityRank(item.Severity) > severityRank(combined.Severity) {
			combined.Severity = item.Severity
		}
		if combined.Priority == "" || item.Priority != "" && PriorityRank(item.Priority) > PriorityRank(combined.Priority) {
			combined.Priority = item.Priority
		}
		combined.KEV = combined.KEV || item.KEV
		if item.EPSS != nil && (combined.EPSS == nil || *item.EPSS > *combined.EPSS) {
			combined.EPSS = item.EPSS
		}
		combined.CVSSScore = max(combined.CVSSScore, item.CVSSScore)
		if fixOrder[item.Fix] > fixOrder[combined.Fix] {
			combined.Fix, combined.FixedVersion = item.Fix, item.FixedVersion
		}
		combined.Nodes = append(combined.Nodes, NodeVersion{HostID: item.HostID, Host: item.Address, InstalledVersion: item.InstalledVersion,
			FixedVersion: item.FixedVersion, Fix: item.Fix})
	}
	result := make([]ClusterVulnerability, 0, len(order))
	for _, key := range order {
		result = append(result, *byKey[key])
	}
	sort.SliceStable(result, func(i, j int) bool {
		if a, b := severityRank(result[i].Severity), severityRank(result[j].Severity); a != b {
			return a > b
		}
		if a, b := len(result[i].Nodes), len(result[j].Nodes); a != b {
			return a > b
		}
		return result[i].Package < result[j].Package
	})
	return result
}

// CombinedCounts are a cluster's vulnerabilities counted once, as a host's
// latest report counts its own.
type CombinedCounts struct {
	Findings int            `json:"findings"`
	Severity SeverityCounts `json:"severity"`
	Fixes    FixSummary     `json:"fixes"`
	Exploit  ExploitCounts  `json:"exploit"`
	// Scanned counts the nodes with package results.
	Scanned int `json:"scanned"`
}

func countCombined(vulnerabilities []ClusterVulnerability) CombinedCounts {
	counts := CombinedCounts{Fixes: FixSummary{Counts: map[string]int{}}}
	known, likely := map[string]bool{}, map[string]bool{}
	for _, item := range vulnerabilities {
		counts.Findings++
		counts.Severity.add(item.Severity)
		counts.Fixes.Counts[item.Fix]++
		if actionableFix(item.Fix) {
			counts.Fixes.Actionable.add(item.Severity)
		}
		switch item.Priority {
		case "exploited":
			known[item.CVE] = known[item.CVE] || actionableFix(item.Fix)
		case "likely":
			likely[item.CVE] = true
		}
	}
	counts.Exploit.Known, counts.Exploit.Likely = len(known), len(likely)
	for _, fixable := range known {
		if fixable {
			counts.Exploit.KnownFixable++
		}
	}
	return counts
}

// ClusterCombinedCounts counts every cluster's node vulnerabilities once,
// by cluster ID.
func ClusterCombinedCounts() (map[string]CombinedCounts, error) {
	affected, cves, err := queryLatestFindings(" AND h.cluster_id != ''")
	if err != nil {
		return nil, err
	}
	byCluster := map[string][]int{}
	scanned := map[string]map[string]bool{}
	for index, item := range affected {
		byCluster[item.ClusterID] = append(byCluster[item.ClusterID], index)
	}
	result := map[string]CombinedCounts{}
	for cluster, indexes := range byCluster {
		var items []AffectedPackage
		var ids []string
		scanned[cluster] = map[string]bool{}
		for _, index := range indexes {
			items = append(items, affected[index])
			ids = append(ids, cves[index])
			scanned[cluster][affected[index].HostID] = true
		}
		counts := countCombined(combineVulnerabilities(items, ids))
		counts.Scanned = len(scanned[cluster])
		result[cluster] = counts
	}
	return result, nil
}

// GetClusterFindings combines a check's latest findings on a cluster's
// nodes: packages, malware or integrity.
func GetClusterFindings(clusterID, check string) (ClusterFindings, error) {
	result := ClusterFindings{Check: check}
	nodes, err := ClusterNodes(clusterID)
	if err != nil {
		return result, err
	}
	result.Nodes = len(nodes)
	for _, node := range nodes {
		if node.Excluded {
			result.Excluded++
		}
	}
	db, err := database()
	if err != nil {
		return result, err
	}
	if err := db.QueryRow(`SELECT COUNT(DISTINCT s.host_id) FROM scans s JOIN hosts h ON h.id = s.host_id
		WHERE h.cluster_id = ? AND s.status = ? AND s.checks LIKE ?`, clusterID, ScanSucceeded, "%,"+check+",%").Scan(&result.Checked); err != nil {
		return result, err
	}
	if check == CheckPackages {
		affected, cves, err := queryLatestFindings(" AND h.cluster_id = ?", clusterID)
		if err != nil {
			return result, err
		}
		result.Vulnerabilities = combineVulnerabilities(affected, cves)
		for _, item := range result.Vulnerabilities {
			result.Counts.add(item.Severity)
		}
		return result, nil
	}
	result.Findings, err = clusterCheckFindings(db, clusterID, check)
	for _, item := range result.Findings {
		result.Counts.add(item.Severity)
	}
	return result, err
}

func clusterCheckFindings(db *sql.DB, clusterID, check string) ([]ClusterCheckFinding, error) {
	rows, err := db.Query(`WITH latest AS (
		SELECT id FROM (
			SELECT s.id, ROW_NUMBER() OVER (PARTITION BY s.host_id ORDER BY s.started_at DESC, s.rowid DESC) AS n
			FROM scans s JOIN hosts h ON h.id = s.host_id
			WHERE h.cluster_id = ? AND s.status = ? AND s.checks LIKE ?
		) WHERE n = 1
	)
	SELECT s.host_id, COALESCE(NULLIF(h.display_name, ''), h.address), f.rule, f.severity, f.title, f.detail, f.evidence
	FROM latest JOIN scans s ON s.id = latest.id JOIN hosts h ON h.id = s.host_id
	JOIN check_findings f ON f.scan_id = s.id AND f.check_id = ?
	ORDER BY COALESCE(NULLIF(h.display_name, ''), h.address)`, clusterID, ScanSucceeded, "%,"+check+",%", check)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKey := map[string]*ClusterCheckFinding{}
	var order []string
	for rows.Next() {
		var hostID, host string
		var item ClusterCheckFinding
		if err := rows.Scan(&hostID, &host, &item.Rule, &item.Severity, &item.Title, &item.Detail, &item.Evidence); err != nil {
			return nil, err
		}
		// The same rule about the same file or setting, on several nodes.
		key := item.Rule + "\x00" + item.Evidence + "\x00" + item.Title
		combined, ok := byKey[key]
		if !ok {
			combined = &item
			byKey[key] = combined
			order = append(order, key)
		}
		combined.Nodes = append(combined.Nodes, NodeVersion{HostID: hostID, Host: host})
	}
	result := make([]ClusterCheckFinding, 0, len(order))
	for _, key := range order {
		result = append(result, *byKey[key])
	}
	sort.SliceStable(result, func(i, j int) bool {
		if a, b := severityRank(result[i].Severity), severityRank(result[j].Severity); a != b {
			return a > b
		}
		return strings.Compare(result[i].Title, result[j].Title) < 0
	})
	return result, rows.Err()
}

// updateClusterTrend records a cluster's vulnerabilities on a day, counted
// once across its nodes, after one of its nodes' package scans.
func updateClusterTrend(hostID, day string) error {
	host, err := GetHost(hostID)
	if err != nil || !host.IsNode() {
		return err
	}
	counts, err := ClusterCombinedCounts()
	if err != nil {
		return err
	}
	combined := counts[host.ClusterID]
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT OR REPLACE INTO host_trends (host_id, day, critical, high, medium, low, unknown, exploited, likely)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, host.ClusterID, day, combined.Severity.Critical, combined.Severity.High, combined.Severity.Medium,
		combined.Severity.Low, combined.Severity.Unknown, combined.Exploit.Known, combined.Exploit.Likely)
	return err
}
