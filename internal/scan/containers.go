package scan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/advisory"
	"deaconguard/internal/checks"
	"deaconguard/internal/containers"
	"deaconguard/internal/osv"
	"deaconguard/internal/scanner"
)

// scanPackages evaluates a package inventory; tests replace it.
var scanPackages = scanner.Scan

// maxContainerFindings bounds the findings kept for each container.
const maxContainerFindings = 300

// collectContainers lists the running containers and reads each one. It
// needs root, as the agent has, to see other users' processes and read
// their containers' files.
func collectContainers(executor *checks.Executor) checks.Result {
	if os.Geteuid() != 0 {
		return checks.Result{Status: checks.StatusSkipped, Summary: "Needs root",
			Notes:    []string{"Reading running containers needs root: scan this machine with its DeaconGuard agent, which runs as root."},
			Findings: []checks.Finding{}}
	}
	output, _, privileged, err := executor.RunPrivileged(containers.ListCommand, 1<<20, 2*time.Minute)
	if err != nil && len(output) == 0 {
		return checks.Result{Status: checks.StatusFailed, Summary: "Check could not run", Error: "list the running containers: " + err.Error(),
			Findings: []checks.Finding{}, Notes: []string{}}
	}
	kernel, _, _ := executor.Run("uname -r", 256, time.Minute)
	result := checks.Result{Status: checks.StatusCompleted, Privileged: privileged, Findings: []checks.Finding{}, Notes: []string{}}
	for _, container := range containers.ParseList(output) {
		read := containers.Read(container)
		result.Containers = append(result.Containers, checks.ContainerResult{
			Container: container, Inventory: &read, HostKernel: strings.TrimSpace(string(kernel)),
		})
	}
	if len(result.Containers) == 0 {
		result.Summary = "No running containers"
		result.Notes = append(result.Notes, "Docker, Podman and crictl (containerd, CRI-O) were asked; none listed a running container.")
	} else {
		result.Summary = fmt.Sprintf("Found %d running containers", len(result.Containers))
	}
	return result
}

// EvaluateContainers checks the containers an agent read, in place in the
// report's check results, as a scan run here would have.
func EvaluateContainers(report map[string]any, emit func(Event)) error {
	raw, ok := report["check_results"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var results map[string]checks.Result
	if err := json.Unmarshal(encoded, &results); err != nil {
		return fmt.Errorf("read check results: %w", err)
	}
	result, ok := results[checks.Containers]
	if !ok {
		return nil
	}
	progress := &reporter{emit: emit}
	progress.startPhase(checks.Containers, "Checking the containers the agent read")
	if result.Status == checks.StatusCompleted || result.Status == checks.StatusPartial {
		evaluateContainers(&result, progress)
	}
	progress.findings(result)
	progress.endPhase(result.Status, result.Summary)
	results[checks.Containers] = result
	report["check_results"] = results
	return nil
}

type ranked struct {
	finding   checks.Finding
	rank      int
	exploited bool
	fixable   bool
}

// evaluateContainers checks every container's packages against its
// distribution's advisories and its libraries against OSV. Containers with
// the same contents, such as replicas of one image, are checked once.
func evaluateContainers(result *checks.Result, progress *reporter) {
	verdicts := make(map[string]*checks.ContainerResult)
	var all []ranked
	vulnerableContainers, exploitedTotal := 0, 0
	for index := range result.Containers {
		container := &result.Containers[index]
		inventory := container.Inventory
		container.Inventory = nil
		if inventory == nil {
			container.Error = "the agent sent nothing for this container"
			continue
		}
		key := fingerprint(inventory)
		if done, seen := verdicts[key]; seen {
			copyVerdict(container, done, inventory)
		} else {
			progress.info("Checking container %s (%s)", container.Name, container.Image)
			checkContainer(container, inventory)
			verdicts[key] = container
		}
		if len(container.Findings) > 0 || container.Exploited > 0 {
			vulnerableContainers++
		}
		exploitedTotal += container.Exploited
		for _, finding := range container.Findings {
			all = append(all, ranked{finding: finding, rank: severityRank(finding.Severity), exploited: strings.Contains(finding.Detail, "Known to be exploited")})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].exploited != all[j].exploited {
			return all[i].exploited
		}
		return all[i].rank > all[j].rank
	})
	result.Findings = []checks.Finding{}
	for index, item := range all {
		if index >= 200 {
			result.Notes = append(result.Notes, fmt.Sprintf("%d more container findings are listed under each container.", len(all)-200))
			break
		}
		result.Findings = append(result.Findings, item.finding)
	}
	total := 0
	for _, container := range result.Containers {
		for _, count := range container.Severity {
			total += count
		}
	}
	result.Summary = fmt.Sprintf("%d running containers: %d vulnerabilities, %d to fix in %d containers", len(result.Containers), total, len(all), vulnerableContainers)
	if exploitedTotal > 0 {
		result.Summary += fmt.Sprintf(", %d known to be exploited", exploitedTotal)
	}
}

func fingerprint(inventory *containers.Inventory) string {
	sum := sha256.New()
	encoded, _ := json.Marshal(struct {
		OS, DPKG, RPM, APK string
		Libraries          any
	}{inventory.OSRelease, inventory.DPKGStatus, inventory.RPMQuery, inventory.APKInstalled, inventory.Libraries})
	sum.Write(encoded)
	return fmt.Sprintf("%x", sum.Sum(nil))
}

// copyVerdict gives a container the verdict of another with the same
// contents, with its own name in the findings.
func copyVerdict(container, done *checks.ContainerResult, inventory *containers.Inventory) {
	container.OS, container.Lifecycle, container.Packages, container.Libraries = done.OS, done.Lifecycle, done.Packages, done.Libraries
	container.Severity, container.Exploited, container.Fixable, container.Error = done.Severity, done.Exploited, done.Fixable, done.Error
	container.Notes = append(append([]string(nil), inventory.Notes...), done.Notes...)
	for _, finding := range done.Findings {
		finding.Title = container.Name + strings.TrimPrefix(finding.Title, done.Name)
		finding.Evidence = container.Image
		container.Findings = append(container.Findings, finding)
	}
}

func checkContainer(container *checks.ContainerResult, inventory *containers.Inventory) {
	evaluateContainer(container, inventory)
}

// evaluateContainer checks a container's packages and libraries, keeps the
// findings to fix in container, and returns every vulnerability, most urgent
// first, with the package report, if its packages could be checked.
func evaluateContainer(container *checks.ContainerResult, inventory *containers.Inventory) ([]ranked, *scanner.Report) {
	var packages *scanner.Report
	container.Severity = map[string]int{}
	container.FixableSeverity = map[string]int{}
	container.Notes = append(container.Notes, inventory.Notes...)
	var findings []ranked
	if inventory.OSRelease != "" && (inventory.DPKGStatus != "" || inventory.RPMQuery != "" || inventory.APKInstalled != "") {
		kernel := container.HostKernel
		if kernel == "" {
			kernel = "unknown"
		}
		report, err := scanPackages(inventory.OSRelease, inventory.DPKGStatus, inventory.RPMQuery, inventory.APKInstalled, kernel, nil, time.Now().UTC())
		if err != nil {
			container.Error = "Packages not checked: " + err.Error()
		} else {
			packages = &report
			container.OS, container.Packages = report.OS, report.PackageCount
			life := report.Lifecycle
			container.Lifecycle = &life
			for _, f := range report.Findings {
				severity := strings.ToUpper(f.Severity)
				container.Severity[severity]++
				exploited := f.Exploit != nil && f.Exploit.KEV
				if exploited {
					container.Exploited++
				}
				fixable := f.Fix == advisory.FixAvailable
				if fixable {
					container.Fixable++
					container.FixableSeverity[severity]++
				}
				detail := "No fixed version yet."
				if f.FixedVersion != "" {
					detail = "Fixed in " + f.FixedVersion + ": update the image."
				}
				if exploited {
					detail += " Known to be exploited (CISA KEV)."
				}
				findings = append(findings, ranked{finding: checks.Finding{
					Rule: f.ID, Severity: severity, Detail: detail, Evidence: container.Image,
					Title: fmt.Sprintf("%s: %s %s (%s): %s", container.Name, f.Package, f.InstalledVersion, report.OS, f.ID),
				}, rank: severityRank(severity), exploited: exploited, fixable: fixable})
			}
		}
	} else if inventory.OSRelease != "" {
		container.Notes = append(container.Notes, "No package database was found: a static or scratch image; only its libraries are checked.")
	}
	if inventory.Libraries != nil && len(inventory.Libraries.Libraries) > 0 {
		container.Libraries = len(inventory.Libraries.Libraries)
		libs := checks.Result{Status: checks.StatusCompleted, Libraries: inventory.Libraries}
		osv.Evaluate(&libs, osv.NewClient(), &http.Client{Timeout: 60 * time.Second}, time.Now().UTC())
		if libs.Status == checks.StatusFailed {
			container.Notes = append(container.Notes, libs.Error)
		}
		for _, f := range libs.Findings {
			container.Severity[f.Severity]++
			exploited := strings.Contains(f.Detail, "Known to be exploited")
			if exploited {
				container.Exploited++
			}
			fixable := !strings.Contains(f.Detail, "No fixed version")
			if fixable {
				container.Fixable++
				container.FixableSeverity[f.Severity]++
			}
			f.Title = container.Name + ": " + f.Title
			findings = append(findings, ranked{finding: f, rank: severityRank(f.Severity), exploited: exploited, fixable: fixable})
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].exploited != findings[j].exploited {
			return findings[i].exploited
		}
		return findings[i].rank > findings[j].rank
	})
	var toFix []checks.Finding
	for _, item := range findings {
		if item.fixable || item.exploited {
			toFix = append(toFix, item.finding)
		}
	}
	if len(toFix) > maxContainerFindings {
		container.Notes = append(container.Notes, fmt.Sprintf("%d more findings weren't listed.", len(toFix)-maxContainerFindings))
		toFix = toFix[:maxContainerFindings]
	}
	container.Findings = toFix
	return findings, packages
}

func severityRank(severity string) int {
	return map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[strings.ToUpper(severity)]
}

// EvaluateImage checks an image's packages and libraries, as a running
// container's are checked.
func EvaluateImage(inventory containers.Inventory) checks.ContainerResult {
	return CheckImage(inventory).Result
}

// ImageCheck is an image's check with what pipelines need besides: every
// vulnerability, and the package list for an SBOM.
type ImageCheck struct {
	Result checks.ContainerResult
	// Vulnerabilities is every vulnerability found, fixable or not, most
	// urgent first; Result lists only those to fix, at most 300.
	Vulnerabilities []Vulnerability
	// Report is the image as a scan report, for sbom.Build.
	Report map[string]any
}

// Vulnerability is one vulnerability in an image.
type Vulnerability struct {
	checks.Finding
	Fixable   bool
	Exploited bool
}

// CheckImage checks an image's packages and libraries, as a running
// container's are checked.
func CheckImage(inventory containers.Inventory) ImageCheck {
	result := checks.ContainerResult{Container: inventory.Container}
	findings, packages := evaluateContainer(&result, &inventory)
	check := ImageCheck{Result: result, Vulnerabilities: make([]Vulnerability, 0, len(findings))}
	for _, item := range findings {
		check.Vulnerabilities = append(check.Vulnerabilities, Vulnerability{Finding: item.finding, Fixable: item.fixable, Exploited: item.exploited})
	}
	report := map[string]any{"address": inventory.Name, "os": result.OS, "scanned_at": time.Now().UTC().Format(time.RFC3339)}
	if packages != nil {
		report["distro"], report["package_manager"], report["installed_packages"] = packages.Distro, packages.PackageManager, packages.InstalledPackages
	}
	if inventory.Libraries != nil {
		report["check_results"] = map[string]any{"libraries": map[string]any{"libraries": inventory.Libraries}}
	}
	check.Report = report
	return check
}
