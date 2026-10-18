package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/images"
	"deaconguard/internal/scan"
)

// errFindings makes `image scan --fail-on` exit with status 4.
var errFindings = errors.New("findings at or above the --fail-on severity")

const imageUsage = "usage: deaconguard image scan IMAGE [--platform linux/amd64] [--fail-on critical|high|medium|low] [--json]"

// runImage handles `deaconguard image scan`: it reads an image from its
// registry, without running it, and checks it as a running container is
// checked.
func runImage(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "scan" {
		return errors.New(imageUsage)
	}
	platform := "linux/" + runtime.GOARCH
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		platform = "linux/amd64"
	}
	reference, failOn, asJSON := "", "", false
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
			asJSON = true
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
	ref, err := images.ParseReference(reference)
	if err != nil {
		return err
	}
	// A login for the image's registry, from the environment: a CI job's
	// secrets, for example.
	client := images.NewClient(func(registry string) (images.Credentials, bool) {
		user := os.Getenv("DEACONGUARD_REGISTRY_USERNAME")
		return images.Credentials{Username: user, Password: os.Getenv("DEACONGUARD_REGISTRY_PASSWORD")}, user != ""
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	progress := func(line string) {
		if !asJSON {
			fmt.Fprintln(diagnostics, line)
		}
	}
	inventory, resolved, err := images.Read(ctx, client, ref, platform, progress)
	if err != nil {
		return err
	}
	progress("Checking the image's packages and libraries")
	result := scan.EvaluateImage(inventory)
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(map[string]any{"image": ref.String(), "digest": resolved.Digest, "platform": platform, "result": result}); err != nil {
			return err
		}
	} else {
		showImage(result, resolved, platform, output)
	}
	if failOn != "" && atOrAbove(result, failOn) {
		return errFindings
	}
	return nil
}

func atOrAbove(result checks.ContainerResult, level string) bool {
	order := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	threshold := 0
	for index, name := range order {
		if name == level {
			threshold = index
		}
	}
	for index, name := range order {
		if index >= threshold && result.Severity[name] > 0 {
			return true
		}
	}
	return false
}

func showImage(result checks.ContainerResult, resolved images.Resolved, platform string, output io.Writer) {
	fmt.Fprintf(output, "Image: %s\nDigest: %s (%s)\n", result.Image, resolved.Digest, platform)
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
