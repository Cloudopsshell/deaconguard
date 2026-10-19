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
	kept := result.Findings[:0]
	for _, f := range result.Findings {
		if !skip[f.Rule] {
			kept = append(kept, f)
		}
	}
	result.Findings = kept
	items := make([]ciout.Item, 0, len(result.Findings))
	for _, f := range result.Findings {
		items = append(items, ciout.Item{Rule: f.Rule, Severity: f.Severity, Title: f.Title, Detail: f.Detail,
			HelpURI: "https://docs.deaconguard.io/usage/config-checks#rules", URI: f.File, Line: f.Line, Group: f.File})
	}
	var report []byte
	switch format {
	case "json":
		report, err = json.MarshalIndent(result, "", "  ")
		report = append(report, '\n')
	case "sarif":
		report, err = ciout.SARIF(items)
	case "junit":
		report, err = ciout.JUnit(strings.Join(paths, " "), items, func(item ciout.Item) bool {
			return failOn == "" || severityAtOrAbove(item.Severity, failOn)
		})
	}
	if err != nil {
		return err
	}
	switch {
	case format == "table":
		showConfig(result, output)
	case outputFile == "":
		output.Write(report)
	default:
		if err := os.WriteFile(outputFile, report, 0o644); err != nil {
			return err
		}
		showConfig(result, output)
		fmt.Fprintf(output, "Wrote the %s report to %s\n", format, outputFile)
	}
	for _, note := range result.Notes {
		fmt.Fprintf(diagnostics, "Note: %s\n", note)
	}
	if failOn != "" {
		for _, f := range result.Findings {
			if severityAtOrAbove(f.Severity, failOn) {
				return errFindings
			}
		}
	}
	return nil
}

func showConfig(result iac.Result, output io.Writer) {
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], strings.ToLower(severity)))
		}
	}
	fmt.Fprintf(output, "Checked %d %s: %d %s", len(result.Files), pluralWord(len(result.Files), "file", "files"),
		len(result.Findings), pluralWord(len(result.Findings), "finding", "findings"))
	if len(parts) > 0 {
		fmt.Fprintf(output, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(output)
	for _, f := range result.Findings {
		fmt.Fprintf(output, "  %-8s %s:%d %s [%s]\n           %s\n", f.Severity, f.File, f.Line, f.Title, f.Rule, f.Detail)
	}
}

func pluralWord(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}
