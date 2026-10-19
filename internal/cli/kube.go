package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"deaconguard/internal/iac"
	"deaconguard/internal/images"
	"deaconguard/internal/kube"
	"deaconguard/internal/scan"
)

const kubeUsage = "usage: deaconguard kube scan [--kubeconfig FILE] [--context NAME] [--include-system] [--images] " +
	"[--fail-on critical|high|medium|low] [--skip RULE,...] [--format table|json|sarif|junit] [--output FILE]"

// maxClusterImages bounds --images.
const maxClusterImages = 100

// runKube handles `deaconguard kube scan`: it reads a cluster through its
// API, read-only, and checks its workloads, roles, namespaces, version and
// control plane.
func runKube(arguments []string, output, diagnostics io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "scan" {
		return errors.New(kubeUsage)
	}
	kubeconfig, contextName, failOn, format, outputFile := "", "", "", "table", ""
	includeSystem, withImages := false, false
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
		var err error
		switch {
		case argument == "--include-system":
			includeSystem = true
		case argument == "--images":
			withImages = true
		case argument == "--json":
			format = "json"
		case strings.HasPrefix(argument, "--kubeconfig"):
			kubeconfig, err = value()
		case strings.HasPrefix(argument, "--context"):
			contextName, err = value()
		case strings.HasPrefix(argument, "--fail-on"):
			failOn, err = value()
			failOn = strings.ToUpper(failOn)
			if err == nil && !slices.Contains(severityOrder, failOn) {
				err = errors.New("--fail-on is critical, high, medium or low")
			}
		case strings.HasPrefix(argument, "--skip"):
			var v string
			v, err = value()
			for _, id := range strings.Split(v, ",") {
				if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
					skip[id] = true
				}
			}
		case strings.HasPrefix(argument, "--format"):
			format, err = value()
			if err == nil && !slices.Contains(configFormats, format) {
				err = fmt.Errorf("--format is one of %s", strings.Join(configFormats, ", "))
			}
		case strings.HasPrefix(argument, "--output") || argument == "-o":
			outputFile, err = value()
		default:
			return errors.New(kubeUsage)
		}
		if err != nil {
			return err
		}
	}
	client, err := kube.Connect(kubeconfig, contextName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	fmt.Fprintf(diagnostics, "Reading the cluster %s (%s), read-only\n", client.Name, client.Server)
	report, err := kube.Scan(ctx, client, kube.Options{IncludeSystem: includeSystem, Releases: kube.OnlineReleases, CVEs: kube.OnlineCVEs})
	if err != nil {
		return err
	}
	if withImages {
		report.Findings = append(report.Findings, checkClusterImages(ctx, report.Images, &report, diagnostics)...)
	} else if len(report.Images) > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf("%d images run in the cluster; --images checks them too", len(report.Images)))
	}
	report.Findings = skipRules(report.Findings, skip)
	return writeFindings(findingsReport{
		findings: report.Findings, notes: report.Notes, document: report, suite: report.Cluster,
		summary: fmt.Sprintf("Cluster %s, Kubernetes %s: %d nodes, %d namespaces, %d workloads", report.Cluster, report.Version, report.Nodes, report.Namespaces, report.Workloads),
	}, format, outputFile, failOn, output, diagnostics)
}

// checkClusterImages reads each running image from its registry, as image
// scan does, and reports those with vulnerabilities to fix.
func checkClusterImages(ctx context.Context, list []string, report *kube.Report, diagnostics io.Writer) []iac.Finding {
	credentials, err := environmentCredentials()
	if err != nil {
		report.Notes = append(report.Notes, err.Error())
		return nil
	}
	client := images.NewClient(credentials)
	if len(list) > maxClusterImages {
		report.Notes = append(report.Notes, fmt.Sprintf("Only the first %d of %d images were checked", maxClusterImages, len(list)))
		list = list[:maxClusterImages]
	}
	var findings []iac.Finding
	failed := 0
	for index, image := range list {
		fmt.Fprintf(diagnostics, "Checking image %d of %d: %s\n", index+1, len(list), image)
		ref, err := images.ParseReference(image)
		if err != nil {
			failed++
			continue
		}
		platform := "linux/amd64"
		if report.Architecture != "" {
			platform = "linux/" + report.Architecture
		}
		inventory, _, err := images.Read(ctx, client, ref, platform, nil)
		if err != nil {
			failed++
			report.Notes = append(report.Notes, "Image "+image+" wasn't checked: "+err.Error())
			continue
		}
		result := scan.CheckImage(inventory).Result
		if result.Fixable == 0 && result.Exploited == 0 {
			continue
		}
		severity := "LOW"
		for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if result.FixableSeverity[level] > 0 {
				severity = level
				break
			}
		}
		if result.Exploited > 0 && rankOf(severity) < rankOf("HIGH") {
			severity = "HIGH"
		}
		var parts []string
		if result.Exploited > 0 {
			parts = append(parts, fmt.Sprintf("%d known to be exploited", result.Exploited))
		}
		parts = append(parts, fmt.Sprintf("%d fixed by a newer build", result.Fixable))
		finding := iac.NewFinding("DG-K8S-050", "k8s/_cluster/image/"+image, 1, fmt.Sprintf("Image %s: %s", image, strings.Join(parts, ", ")),
			"Rebuild the image on an updated base, or update to a newer release, and roll the workloads that use it. deaconguard image scan "+image+" lists each vulnerability.")
		finding.Severity = severity
		findings = append(findings, finding)
	}
	if failed > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf("%d images couldn't be read: private registries need DEACONGUARD_REGISTRY_USERNAME and _PASSWORD", failed))
	}
	return findings
}

func rankOf(severity string) int { return slices.Index(severityOrder, severity) }
