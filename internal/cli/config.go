package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"deaconguard/internal/ciout"
	"deaconguard/internal/iac"
)

const configUsage = "usage: deaconguard config scan PATH... [--fail-on critical|high|medium|low] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]\n" +
	"       deaconguard config rules"

var configFormats = []string{"table", "json", "sarif", "junit"}

// runConfig handles `deaconguard config scan`: it checks Dockerfiles and
// Kubernetes manifests as text, before anything is built or deployed.
func runConfig(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	if len(arguments) == 1 && arguments[0] == "rules" {
		for _, rule := range iac.Rules() {
			fmt.Fprintf(output, "%-11s %-8s %s (%s)\n", rule.ID, rule.Severity, rule.Title, rule.Source)
		}
		return nil
	}
	if len(arguments) == 0 || arguments[0] != "scan" {
		return errors.New(configUsage)
	}
	var paths []string
	failOn, format, outputFile := "", "table", ""
	skip := map[string]bool{}
	rest := arguments[1:]
	for index := 0; index < len(rest); index++ {
		argument := rest[index]
		value := func() (string, error) {
			if name, v, found := strings.Cut(argument, "="); found && strings.HasPrefix(name, "--") {
				return v, nil
			}
			if index+1 >= len(rest) {
				return "", fmt.Errorf("%s needs a value", argument)
			}
			index++
			return rest[index], nil
		}
		switch {
		case strings.HasPrefix(argument, "--fail-on"):
			v, err := value()
			if err != nil {
				return err
			}
			failOn = strings.ToUpper(v)
			if !slices.Contains(severityOrder, failOn) {
				return errors.New("--fail-on is critical, high, medium or low")
			}
		case strings.HasPrefix(argument, "--format"):
			v, err := value()
			if err != nil {
				return err
			}
			if !slices.Contains(configFormats, v) {
				return fmt.Errorf("--format is one of %s", strings.Join(configFormats, ", "))
			}
			format = v
		case strings.HasPrefix(argument, "--output") || argument == "-o":
			v, err := value()
			if err != nil {
				return err
			}
			outputFile = v
		case argument == "--json":
			format = "json"
		case strings.HasPrefix(argument, "--skip"):
			v, err := value()
			if err != nil {
				return err
			}
			for _, id := range strings.Split(v, ",") {
				if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
					skip[id] = true
				}
			}
		case strings.HasPrefix(argument, "-") && argument != "-":
			return errors.New(configUsage)
		default:
			paths = append(paths, argument)
		}
	}
	if len(paths) == 0 {
		return errors.New(configUsage)
	}
	result, err := iac.Scan(paths, input)
	if err != nil {
		return err
	}
	result.Findings = skipRules(result.Findings, skip)
	return writeFindings(findingsReport{
		findings: result.Findings, notes: result.Notes, document: result, suite: strings.Join(paths, " "),
		summary:  fmt.Sprintf("Checked %d %s", len(result.Files), pluralWord(len(result.Files), "file", "files")),
		withLine: true,
	}, format, outputFile, failOn, output, diagnostics)
}

// skipRules leaves out the findings of the rules in skip.
func skipRules(findings []iac.Finding, skip map[string]bool) []iac.Finding {
	kept := make([]iac.Finding, 0, len(findings))
	for _, f := range findings {
		if !skip[f.Rule] {
			kept = append(kept, f)
		}
	}
	return kept
}

// findingsReport is what config and kube scans found, to write.
type findingsReport struct {
	findings []iac.Finding
	notes    []string
	// document is written for --format json; suite names the JUnit suite;
	// summary starts the table, such as "Checked 3 files".
	document any
	suite    string
	summary  string
	// withLine shows file:line; cluster objects have no lines.
	withLine bool
}

// writeFindings writes findings as a table or a report, and returns
// errFindings when one is at or above failOn.
func writeFindings(r findingsReport, format, outputFile, failOn string, output, diagnostics io.Writer) error {
	items := make([]ciout.Item, 0, len(r.findings))
	for _, f := range r.findings {
		help := "https://docs.deaconguard.io/usage/config-checks#rules"
		if strings.HasPrefix(f.Rule, "DG-TLS-") || strings.HasPrefix(f.Rule, "DG-NET-") {
			help = "https://docs.deaconguard.io/usage/network#rules"
		} else if !strings.HasPrefix(f.Rule, "DG-") {
			help = "https://osv.dev/vulnerability/" + f.Rule
		}
		item := ciout.Item{Rule: f.Rule, Severity: f.Severity, Title: f.Title, Detail: f.Detail,
			HelpURI: help, URI: f.File, Line: f.Line, Group: f.File}
		if len(f.STIG) > 0 {
			item.Properties = map[string]any{"stig": f.STIG}
		}
		items = append(items, item)
	}
	var report []byte
	var err error
	switch format {
	case "json":
		report, err = json.MarshalIndent(r.document, "", "  ")
		report = append(report, '\n')
	case "sarif":
		report, err = ciout.SARIF(items)
	case "junit":
		report, err = ciout.JUnit(r.suite, items, func(item ciout.Item) bool {
			return failOn == "" || severityAtOrAbove(item.Severity, failOn)
		})
	}
	if err != nil {
		return err
	}
	switch {
	case format == "table":
		showFindings(r, output)
	case outputFile == "":
		output.Write(report)
	default:
		if err := os.WriteFile(outputFile, report, 0o644); err != nil {
			return err
		}
		showFindings(r, output)
		fmt.Fprintf(output, "Wrote the %s report to %s\n", format, outputFile)
	}
	for _, note := range r.notes {
		fmt.Fprintf(diagnostics, "Note: %s\n", note)
	}
	if failOn != "" {
		for _, f := range r.findings {
			if severityAtOrAbove(f.Severity, failOn) {
				return errFindings
			}
		}
	}
	return nil
}

func showFindings(r findingsReport, output io.Writer) {
	counts := map[string]int{}
	for _, f := range r.findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], strings.ToLower(severity)))
		}
	}
	fmt.Fprintf(output, "%s: %d %s", r.summary, len(r.findings), pluralWord(len(r.findings), "finding", "findings"))
	if len(parts) > 0 {
		fmt.Fprintf(output, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(output)
	for _, f := range r.findings {
		if r.withLine {
			fmt.Fprintf(output, "  %-8s %s:%d %s [%s]\n           %s\n", f.Severity, f.File, f.Line, f.Title, f.Rule, f.Detail)
		} else {
			fmt.Fprintf(output, "  %-8s %s [%s]\n           %s\n", f.Severity, f.Title, f.Rule, f.Detail)
		}
	}
}

func pluralWord(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}
