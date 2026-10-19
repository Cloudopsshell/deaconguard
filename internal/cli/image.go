package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/ciout"
	"deaconguard/internal/containers"
	"deaconguard/internal/images"
	"deaconguard/internal/sbom"
	"deaconguard/internal/scan"
)

// errFindings makes `image scan --fail-on` exit with status 4.
var errFindings = errors.New("findings at or above the --fail-on severity")

const imageUsage = "usage: deaconguard image scan IMAGE|PATH [--platform linux/amd64] [--fail-on critical|high|medium|low] [--ignore-unfixed] " +
	"[--format table|json|sarif|junit|cyclonedx|spdx] [--output FILE]"

// Output formats of `image scan`.
var imageFormats = []string{"table", "json", "sarif", "junit", sbom.CycloneDX, sbom.SPDX}

// runImage handles `deaconguard image scan`: it reads an image from its
// registry, or a local one (a docker save archive, an OCI layout, or a
// folder), without running it, and checks it as a running container is
// checked.
func runImage(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "scan" {
		return errors.New(imageUsage)
	}
	platform := "linux/" + runtime.GOARCH
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		platform = "linux/amd64"
	}
	reference, failOn, format, outputFile, ignoreUnfixed := "", "", "table", "", false
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
		case argument == "--json":
			format = "json"
		case argument == "--ignore-unfixed":
			ignoreUnfixed = true
		case strings.HasPrefix(argument, "--format"):
			v, err := value()
			if err != nil {
				return err
			}
			if !slices.Contains(imageFormats, v) {
				return fmt.Errorf("--format is one of %s", strings.Join(imageFormats, ", "))
			}
			format = v
		case strings.HasPrefix(argument, "--output") || argument == "-o":
			v, err := value()
			if err != nil {
				return err
			}
			outputFile = v
		case strings.HasPrefix(argument, "--platform"):
			v, err := value()
			if err != nil {
				return err
			}
			platform = v
		case strings.HasPrefix(argument, "--fail-on"):
			v, err := value()
			if err != nil {
				return err
			}
			failOn = strings.ToUpper(v)
			if failOn != "CRITICAL" && failOn != "HIGH" && failOn != "MEDIUM" && failOn != "LOW" {
				return errors.New("--fail-on is critical, high, medium or low")
			}
		case strings.HasPrefix(argument, "-") || reference != "":
			return errors.New(imageUsage)
		default:
			reference = argument
		}
	}
	if reference == "" {
		return errors.New(imageUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	// Progress goes to stderr, so it never mixes with a report on stdout.
	progress := func(line string) { fmt.Fprintln(diagnostics, line) }
	var inventory containers.Inventory
	var resolved images.Resolved
	var err error
	if images.IsLocal(reference) {
		inventory, resolved, err = images.ReadLocal(ctx, reference, platform, progress)
	} else {
		ref, parseErr := images.ParseReference(reference)
		if parseErr != nil {
			return parseErr
		}
		// A login for the image's registry, from the environment: a CI
		// job's secrets, for example.
		client := images.NewClient(func(registry string) (images.Credentials, bool) {
			user := os.Getenv("DEACONGUARD_REGISTRY_USERNAME")
			return images.Credentials{Username: user, Password: os.Getenv("DEACONGUARD_REGISTRY_PASSWORD")}, user != ""
		})
		inventory, resolved, err = images.Read(ctx, client, ref, platform, progress)
	}
	if err != nil {
		return err
	}
	progress("Checking the image's packages and libraries")
	check := scan.CheckImage(inventory)
	result := check.Result
	counted := result.Severity
	if ignoreUnfixed {
		counted = result.FixableSeverity
	}
	listed := make([]scan.Vulnerability, 0, len(check.Vulnerabilities))
	for _, v := range check.Vulnerabilities {
		if !ignoreUnfixed || v.Fixable || v.Exploited {
			listed = append(listed, v)
		}
	}

	var report []byte
	switch format {
	case "json":
		var out strings.Builder
		encoder := json.NewEncoder(&out)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(map[string]any{"image": result.Image, "digest": resolved.Digest, "platform": platform, "result": result, "vulnerabilities": vulnerabilityList(listed)})
		report = []byte(out.String())
	case "sarif":
		report, err = ciout.SARIF(result.Image, listed)
	case "junit":
		report, err = ciout.JUnit(result.Image, listed, func(v scan.Vulnerability) bool {
			return failOn == "" || severityAtOrAbove(v.Severity, failOn)
		})
	case sbom.CycloneDX, sbom.SPDX:
		report, _, err = sbom.Build(check.Report, format)
	}
	if err != nil {
		return err
	}
	switch {
	case format == "table":
		showImage(result, resolved, platform, output)
	case outputFile == "":
		output.Write(report)
	default:
		if err := os.WriteFile(outputFile, report, 0o644); err != nil {
			return err
		}
		// The summary still shows in the job's log.
		showImage(result, resolved, platform, output)
		fmt.Fprintf(output, "Wrote the %s report to %s\n", format, outputFile)
	}
	if failOn != "" && atOrAbove(counted, failOn) {
		return errFindings
	}
	return nil
}

// vulnerabilityList is every vulnerability for --format json.
func vulnerabilityList(list []scan.Vulnerability) []map[string]any {
	result := make([]map[string]any, 0, len(list))
	for _, v := range list {
		result = append(result, map[string]any{"id": v.Rule, "severity": v.Severity, "title": v.Title, "detail": v.Detail,
			"fixable": v.Fixable, "known_exploited": v.Exploited})
	}
	return result
}

var severityOrder = []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}

// severityAtOrAbove reports whether severity is level or worse.
func severityAtOrAbove(severity, level string) bool {
	return slices.Index(severityOrder, strings.ToUpper(severity)) >= slices.Index(severityOrder, level)
}

// atOrAbove reports whether counts has a vulnerability at level or worse.
func atOrAbove(counts map[string]int, level string) bool {
	for _, name := range severityOrder {
		if severityAtOrAbove(name, level) && counts[name] > 0 {
			return true
		}
	}
	return false
}

func showImage(result checks.ContainerResult, resolved images.Resolved, platform string, output io.Writer) {
	fmt.Fprintf(output, "Image: %s\n", result.Image)
	if resolved.Digest != "" {
		fmt.Fprintf(output, "Digest: %s (%s)\n", resolved.Digest, platform)
	}
	if result.OS != "" {
		fmt.Fprintf(output, "OS: %s, %d packages\n", result.OS, result.Packages)
		if result.Lifecycle != nil {
			fmt.Fprintf(output, "Release support: %s\n", result.Lifecycle.Note)
		}
	}
	if result.Error != "" {
		fmt.Fprintf(output, "Packages: %s\n", result.Error)
	}
	fmt.Fprintf(output, "Libraries: %d\n", result.Libraries)
	total := 0
	var counts []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if count := result.Severity[severity]; count > 0 {
			total += count
			counts = append(counts, fmt.Sprintf("%d %s", count, strings.ToLower(severity)))
		}
	}
	fmt.Fprintf(output, "Vulnerabilities: %d", total)
	if len(counts) > 0 {
		fmt.Fprintf(output, " (%s)", strings.Join(counts, ", "))
	}
	fmt.Fprintf(output, "; %d fixed by a newer image, %d known to be exploited\n", result.Fixable, result.Exploited)
	for _, note := range result.Notes {
		fmt.Fprintf(output, "Note: %s\n", note)
	}
	for _, finding := range result.Findings {
		title := strings.TrimPrefix(finding.Title, result.Name+": ")
		fmt.Fprintf(output, "  %-8s %s · %s\n", finding.Severity, title, finding.Detail)
	}
}
