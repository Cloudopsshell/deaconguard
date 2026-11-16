package ciout

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// Summary is what a check found, to show on a pipeline's own page: the
// job summary of GitHub Actions, or any place that renders Markdown.
type Summary struct {
	// Heading names what was checked, such as an image.
	Heading string
	// Facts are short lines about it, such as its OS and digest.
	Facts []string
	// FailOn is the --fail-on severity, or ""; Failed whether it was reached.
	FailOn string
	Failed bool
	// Items are the findings; Report names the file with all of them.
	Items  []Item
	Notes  []string
	Report string
}

// summaryListed bounds the findings a summary lists; the report has the rest.
const summaryListed = 20

var summarySeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

func severityRank(severity string) int {
	rank := slices.Index(summarySeverities, strings.ToUpper(severity))
	if rank < 0 {
		return len(summarySeverities)
	}
	return rank
}

// cell makes text safe inside a Markdown table cell: one line, no pipes
// that would end the cell, no HTML, and not longer than limit.
func cell(text string, limit int) string {
	text = strings.Join(strings.Fields(text), " ")
	if runes := []rune(text); len(runes) > limit {
		text = string(runes[:limit-1]) + "…"
	}
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "\\|", "`", "'").Replace(text)
}

// Markdown writes the summary: whether the check passed, the counts by
// severity, and the worst findings with what to do about each.
func Markdown(s Summary) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "### DeaconGuard: %s\n\n", cell(s.Heading, 200))
	counts := map[string]int{}
	for _, item := range s.Items {
		counts[summarySeverities[min(severityRank(item.Severity), len(summarySeverities)-1)]]++
	}
	total := len(s.Items)
	switch {
	case s.Failed:
		fmt.Fprintf(&out, "**Failed:** findings at or above %s.\n\n", strings.ToLower(s.FailOn))
	case s.FailOn != "":
		fmt.Fprintf(&out, "**Passed:** nothing at or above %s.\n\n", strings.ToLower(s.FailOn))
	case total == 0:
		out.WriteString("**Nothing found.**\n\n")
	default:
		out.WriteString("**Checked.** No severity was set to fail on, so findings are only reported.\n\n")
	}
	for _, fact := range s.Facts {
		fmt.Fprintf(&out, "- %s\n", cell(fact, 300))
	}
	if len(s.Facts) > 0 {
		out.WriteString("\n")
	}
	out.WriteString("| Critical | High | Medium | Low | Unknown |\n| ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(&out, "| %d | %d | %d | %d | %d |\n\n", counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["UNKNOWN"])
	if total > 0 {
		// The worst first; among equals, what attackers use, then what an
		// update fixes. The sort is stable, so the check's own order holds.
		items := slices.Clone(s.Items)
		flag := func(item Item, name string) int {
			if set, _ := item.Properties[name].(bool); set {
				return 0
			}
			return 1
		}
		slices.SortStableFunc(items, func(a, b Item) int {
			if order := severityRank(a.Severity) - severityRank(b.Severity); order != 0 {
				return order
			}
			if order := flag(a, "knownExploited") - flag(b, "knownExploited"); order != 0 {
				return order
			}
			return flag(a, "fixable") - flag(b, "fixable")
		})
		out.WriteString("| Severity | Finding | What to do |\n| --- | --- | --- |\n")
		for _, item := range items[:min(total, summaryListed)] {
			finding := cell(item.Title, 200)
			if item.Rule != "" && !strings.Contains(item.Title, item.Rule) {
				finding += " (" + cell(item.Rule, 60) + ")"
			}
			if set, _ := item.Properties["knownExploited"].(bool); set {
				finding += " **known to be exploited**"
			}
			fmt.Fprintf(&out, "| %s | %s | %s |\n", cell(strings.ToLower(item.Severity), 12), finding, cell(item.Detail, 300))
		}
		out.WriteString("\n")
		if total > summaryListed {
			fmt.Fprintf(&out, "%d more ", total-summaryListed)
			if s.Report != "" {
				fmt.Fprintf(&out, "are in the report, `%s`.\n\n", cell(s.Report, 200))
			} else {
				out.WriteString("are in the job's log.\n\n")
			}
		}
	}
	for _, note := range s.Notes {
		fmt.Fprintf(&out, "> %s\n\n", cell(note, 400))
	}
	return []byte(out.String())
}

// AppendSummary adds the summary to file, creating it if needed, so several
// checks in one job each add their own.
func AppendSummary(file string, s Summary) error {
	out, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := out.Write(Markdown(s)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
