package ciout

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkdown(t *testing.T) {
	items := []Item{
		{Rule: "CVE-2026-0001", Severity: "LOW", Title: "zlib 1.3: CVE-2026-0001", Detail: "Fixed in 1.4."},
		{Rule: "CVE-2026-0002", Severity: "HIGH", Title: "openssl 3.0 | <b>bold</b>", Detail: "Fixed in\n3.1.", Properties: map[string]any{"fixable": true}},
		{Rule: "CVE-2026-0003", Severity: "HIGH", Title: "curl 8.0", Detail: "Fixed in 8.1.", Properties: map[string]any{"knownExploited": true}},
		{Rule: "DG-K8S-001", Severity: "CRITICAL", Title: "deploy/shop.yaml:17 container shop is privileged", Detail: "Remove privileged."},
		{Rule: "X", Severity: "", Title: "no severity", Detail: ""},
	}
	out := string(Markdown(Summary{Heading: "image shop:4.2", Facts: []string{"Debian 13, 90 packages"}, FailOn: "HIGH", Failed: true, Items: items, Notes: []string{"a note"}, Report: "deaconguard.sarif"}))
	for _, want := range []string{
		"### DeaconGuard: image shop:4.2\n",
		"**Failed:** findings at or above high.",
		"- Debian 13, 90 packages\n",
		"| 1 | 2 | 0 | 1 | 1 |",
		// A cell stays one cell and one line, and carries no HTML.
		`| high | openssl 3.0 \| &lt;b&gt;bold&lt;/b&gt; (CVE-2026-0002) | Fixed in 3.1. |`,
		// The rule isn't repeated when the title names it.
		"| low | zlib 1.3: CVE-2026-0001 | Fixed in 1.4. |",
		"curl 8.0 (CVE-2026-0003) **known to be exploited**",
		"> a note\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	// The worst first; among equals, what attackers use before the rest.
	order := []string{"container shop is privileged", "curl 8.0", "openssl 3.0", "zlib 1.3", "no severity"}
	last := -1
	for _, title := range order {
		at := strings.Index(out, title)
		if at < last {
			t.Errorf("%q is out of order:\n%s", title, out)
		}
		last = at
	}

	passed := string(Markdown(Summary{Heading: "image shop:4.2", FailOn: "HIGH", Items: items[:1]}))
	if !strings.Contains(passed, "**Passed:** nothing at or above high.") {
		t.Errorf("passed: %s", passed)
	}
	if clean := string(Markdown(Summary{Heading: "x"})); !strings.Contains(clean, "**Nothing found.**") || strings.Contains(clean, "| Severity |") {
		t.Errorf("clean: %s", clean)
	}
	if reported := string(Markdown(Summary{Heading: "x", Items: items})); !strings.Contains(reported, "**Checked.**") {
		t.Errorf("no --fail-on: %s", reported)
	}

	// Only the worst are listed; the rest are counted, with where to find them.
	var many []Item
	for index := range 45 {
		many = append(many, Item{Rule: fmt.Sprintf("CVE-%d", index), Severity: "MEDIUM", Title: fmt.Sprintf("package %d", index)})
	}
	long := string(Markdown(Summary{Heading: "x", Items: many, Report: "r.sarif"}))
	if strings.Count(long, "| medium |") != summaryListed || !strings.Contains(long, "25 more are in the report, `r.sarif`.") {
		t.Errorf("a long list: %s", long)
	}
	if noFile := string(Markdown(Summary{Heading: "x", Items: many})); !strings.Contains(noFile, "25 more are in the job's log.") {
		t.Errorf("a long list without a report: %s", noFile)
	}
}

func TestAppendSummary(t *testing.T) {
	file := filepath.Join(t.TempDir(), "summary.md")
	for _, heading := range []string{"first", "second"} {
		if err := AppendSummary(file, Summary{Heading: heading}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if first, second := strings.Index(string(data), "DeaconGuard: first"), strings.Index(string(data), "DeaconGuard: second"); first < 0 || second < first {
		t.Errorf("two checks in one job: %s", data)
	}
	if err := AppendSummary(filepath.Join(t.TempDir(), "missing", "summary.md"), Summary{}); err == nil {
		t.Error("a file that can't be written gave no error")
	}
}
