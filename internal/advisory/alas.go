package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"

	"opsarmor/internal/inventory"
	"opsarmor/internal/platform"
	"opsarmor/internal/version"
)

const maxBulletinBytes = 4 << 20

var alasTitlePattern = regexp.MustCompile(`^(ALAS2023-[0-9]+-[0-9]+)\s+\(([^)]+)\):\s*(.+)$`)
var cvePattern = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]+`)

type alasRSS struct {
	Channel struct {
		Items []alasRSSItem `xml:"item"`
	} `xml:"channel"`
}

type alasRSSItem struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Link        string `xml:"link"`
}

type bulletinFetcher func(context.Context, string) ([]byte, error)

func EvaluateAmazonLinux2023(target platform.Platform, packages []inventory.Package, rssData []byte, client *http.Client) (DebianEvaluation, error) {
	if target.Family != platform.AmazonLinux {
		return DebianEvaluation{}, fmt.Errorf("ALAS 2023 evaluator cannot evaluate %s", target.Family)
	}
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	fetcher := func(ctx context.Context, url string) ([]byte, error) {
		digest := sha256.Sum256([]byte(url))
		cached, err := LoadFeed(url, "alas-bulletin-"+hex.EncodeToString(digest[:8]), client, time.Time{})
		if err != nil {
			return nil, err
		}
		return cached.Data, nil
	}
	return evaluateAmazonLinux2023RSS(context.Background(), packages, rssData, fetcher)
}

func evaluateAmazonLinux2023RSS(ctx context.Context, packages []inventory.Package, rssData []byte, fetch bulletinFetcher) (DebianEvaluation, error) {
	var feed alasRSS
	if err := xml.Unmarshal(rssData, &feed); err != nil {
		return DebianEvaluation{}, fmt.Errorf("parse Amazon Linux 2023 ALAS feed: %w", err)
	}
	if len(feed.Channel.Items) == 0 {
		return DebianEvaluation{}, fmt.Errorf("Amazon Linux 2023 ALAS feed contains no advisories")
	}
	packagesBySource := make(map[string][]inventory.Package)
	for _, item := range packages {
		packagesBySource[item.Source] = append(packagesBySource[item.Source], item)
	}
	result := DebianEvaluation{Findings: make([]Finding, 0), Unsupported: make([]Unsupported, 0)}
	for _, item := range feed.Channel.Items {
		match := alasTitlePattern.FindStringSubmatch(strings.TrimSpace(item.Title))
		if len(match) != 4 {
			continue
		}
		advisoryID, severity, sourcePackage := match[1], normalizeSeverity(match[2]), strings.TrimSpace(match[3])
		affected := packagesBySource[sourcePackage]
		if len(affected) == 0 {
			continue
		}
		cves := uniqueStrings(cvePattern.FindAllString(item.Description, -1))
		if len(cves) == 0 {
			continue
		}
		bulletin, err := fetch(ctx, item.Link)
		if err != nil {
			for _, cve := range cves {
				result.Unsupported = append(result.Unsupported, Unsupported{
					ID: cve, Title: item.Title, Reason: "could not read official ALAS bulletin: " + err.Error(),
				})
			}
			continue
		}
		newPackages, err := parseALASNewPackages(bulletin)
		if err != nil {
			for _, cve := range cves {
				result.Unsupported = append(result.Unsupported, Unsupported{
					ID: cve, Title: item.Title, Reason: "could not parse official ALAS package versions: " + err.Error(),
				})
			}
			continue
		}
		matchedPackage := false
		for _, installed := range affected {
			fixedVersion := alasFixedVersion(installed, newPackages)
			if fixedVersion == "" {
				continue
			}
			result.Evaluated += len(cves)
			comparison, err := version.RPM(installed.Version, fixedVersion)
			if err != nil {
				return DebianEvaluation{}, fmt.Errorf("compare ALAS package %s versions: %w", installed.Name, err)
			}
			matchedPackage = true
			if comparison < 0 {
				for _, cve := range cves {
					result.Findings = append(result.Findings, Finding{
						ID: cve, Package: installed.Name, InstalledVersion: installed.Version,
						FixedVersion: fixedVersion, Severity: severity, URL: item.Link, Title: item.Title,
					})
				}
			}
		}
		if !matchedPackage {
			for _, cve := range cves {
				result.Unsupported = append(result.Unsupported, Unsupported{
					ID: cve, Title: item.Title, Reason: "ALAS bulletin had no replacement RPM matching installed package name and architecture",
				})
			}
		}
		_ = advisoryID
	}
	return result, nil
}

func parseALASNewPackages(bulletin []byte) (map[string][]string, error) {
	document, err := html.Parse(bytes.NewReader(bulletin))
	if err != nil {
		return nil, err
	}
	section := findHTMLID(document, "new_packages")
	if section == nil {
		return nil, fmt.Errorf("bulletin contains no New Packages section")
	}
	text := strings.ReplaceAll(htmlText(section), "\u00a0", " ")
	result := make(map[string][]string)
	for _, token := range strings.Fields(text) {
		if strings.HasPrefix(token, "src:") || strings.Contains(token, "://") {
			continue
		}
		if !strings.Contains(token, ".") || !strings.Contains(token, "-") {
			continue
		}
		result[token] = append(result[token], token)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("bulletin contains no parseable replacement package names")
	}
	return result, nil
}

func alasFixedVersion(installed inventory.Package, packageFiles map[string][]string) string {
	prefix := installed.Name + "-"
	suffix := "." + installed.Arch
	for file := range packageFiles {
		if !strings.HasPrefix(file, prefix) || !strings.HasSuffix(file, suffix) {
			continue
		}
		versionRelease := strings.TrimSuffix(strings.TrimPrefix(file, prefix), suffix)
		versionPart, releasePart, found := strings.Cut(versionRelease, "-")
		if !found || versionPart == "" || releasePart == "" {
			continue
		}
		fixed := versionPart + "-" + releasePart
		if epoch, _, found := strings.Cut(installed.Version, ":"); found {
			fixed = epoch + ":" + fixed
		}
		return fixed
	}
	return ""
}

func findHTMLID(node *html.Node, id string) *html.Node {
	if node.Type == html.ElementNode {
		for _, attribute := range node.Attr {
			if attribute.Key == "id" && attribute.Val == id {
				return node
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findHTMLID(child, id); found != nil {
			return found
		}
	}
	return nil
}

func htmlText(node *html.Node) string {
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
			builder.WriteByte(' ')
		}
		if current.Type == html.ElementNode && current.Data == "br" {
			builder.WriteByte('\n')
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return builder.String()
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
