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
	"deaconguard/internal/lifecycle"
	"deaconguard/internal/osv"
	"deaconguard/internal/scanner"
)

// scanPackages evaluates a package inventory; tests replace it.
var scanPackages = scanner.Scan

// maxContainerFindings bounds the findings to fix kept for each container,
// and maxContainerVulnerabilities all of its vulnerabilities.
const (
	maxContainerFindings        = 300
	maxContainerVulnerabilities = 1000
)

// collectContainers lists the containers and reads each running one; a
// stopped container has no files to read, and is only listed. It needs
// root, as the agent has, to see other users' processes and read their
// containers' files.
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
	running := 0
	for _, container := range containers.ParseList(output) {
		if !container.Running() {
			result.Containers = append(result.Containers, checks.ContainerResult{Container: container})
			continue
		}
		running++
		read := containers.Read(container)
		result.Containers = append(result.Containers, checks.ContainerResult{
			Container: read.Container, Inventory: &read, HostKernel: strings.TrimSpace(string(kernel)),
		})
	}
	switch {
	case len(result.Containers) == 0:
		result.Summary = "No containers"
		result.Notes = append(result.Notes, "Docker, Podman and crictl (containerd, CRI-O) were asked; none listed a container.")
	case running == 0:
		result.Summary = fmt.Sprintf("Found %d containers; none running", len(result.Containers))
		result.Notes = append(result.Notes, "No container is running, so none could be read. Scan their images on the Images page instead.")
	default:
		result.Summary = fmt.Sprintf("Found %d running containers", running)
	}
	return result
}

// runningContainers lists the running containers and finds their own
// files, for the malware checks. It needs root, as collectContainers does;
// without it, or with no container tools, there are none.
func runningContainers(executor *checks.Executor) ([]containers.Writable, int) {
	if os.Geteuid() != 0 {
		return nil, 0
	}
	output, _, _, err := executor.RunPrivileged(containers.ListCommand, 1<<20, 2*time.Minute)
	if err != nil && len(output) == 0 {
		return nil, 0
	}
	return containers.FindWritable(containers.ParseList(output))
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
	vulnerableContainers, exploitedTotal, stopped := 0, 0, 0
	for index := range result.Containers {
		container := &result.Containers[index]
		inventory := container.Inventory
		container.Inventory = nil
		if !container.Scanned() {
			stopped++
			continue
		}
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
	incomplete := 0
	for _, container := range result.Containers {
		if container.Error != "" {
			incomplete++
		}
	}
	counted := fmt.Sprintf("%d running containers", len(result.Containers)-stopped)
	if stopped > 0 {
		counted = fmt.Sprintf("%d containers, %d running", len(result.Containers), len(result.Containers)-stopped)
	}
	result.Summary = fmt.Sprintf("%s: %d vulnerabilities, %d to fix in %d containers", counted, total, len(all), vulnerableContainers)
	if exploitedTotal > 0 {
		result.Summary += fmt.Sprintf(", %d known to be exploited", exploitedTotal)
	}
	if incomplete > 0 {
		result.Summary += fmt.Sprintf("; %d couldn't be fully checked", incomplete)
		result.Notes = append(result.Notes, fmt.Sprintf("%d containers couldn't be fully checked, so they may have vulnerabilities not counted here: each says why.", incomplete))
		if result.Status == checks.StatusCompleted {
			result.Status = checks.StatusPartial
		}
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
	rename := func(finding checks.Finding) checks.Finding {
		finding.Title = container.Name + strings.TrimPrefix(finding.Title, done.Name)
		if finding.Source == "os" {
			finding.Evidence = container.Image
		}
		finding.Container, finding.Image = container.Name, container.Image
		return finding
	}
	for _, finding := range done.Findings {
		container.Findings = append(container.Findings, rename(finding))
	}
	for _, finding := range done.Vulnerabilities {
		container.Vulnerabilities = append(container.Vulnerabilities, rename(finding))
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
		if retired, ok := lifecycle.RetiredRelease(inventory.OSRelease, time.Now().UTC()); err != nil && ok {
			// An ended release has no advisories to check against: what to
			// fix is the release itself.
			life := retired.Lifecycle
			container.OS, container.Lifecycle, container.Packages = retired.Name, &life, packageCount(inventory)
			container.Notes = append(container.Notes, "OS packages not checked: "+retired.Explain())
			container.Severity["HIGH"]++
			container.Fixable++
			container.FixableSeverity["HIGH"]++
			findings = append(findings, ranked{finding: checks.Finding{
				Rule: EndOfLifeRule, Severity: "HIGH", Evidence: container.Image,
				Title:     fmt.Sprintf("%s: %s is end of life", container.Name, retired.Name),
				Detail:    retired.Explain() + " Rebuild the image on a supported base image.",
				Container: container.Name, Image: container.Image, Source: "os", Package: retired.Distribution, Version: retired.Version,
				Ecosystem: retired.Name, Summary: "End of life: no security fixes for this release", Fixed: retired.Upgrade, Fixable: true,
			}, rank: severityRank("HIGH"), fixable: true})
		} else if err != nil {
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
				summary := strings.TrimSpace(f.Title)
				if summary == "" || summary == f.ID {
					summary = ""
				}
				fixed := ""
				if fixable {
					fixed = f.FixedVersion
				}
				findings = append(findings, ranked{finding: checks.Finding{
					Rule: f.ID, Severity: severity, Detail: detail, Evidence: container.Image,
					Title:     fmt.Sprintf("%s: %s %s (%s): %s", container.Name, f.Package, f.InstalledVersion, report.OS, f.ID),
					Container: container.Name, Image: container.Image, Source: "os", Package: f.Package, Version: f.InstalledVersion,
					Ecosystem: report.OS, Summary: summary, Fixed: fixed, Fixable: fixable, Exploited: exploited,
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
			// Not checked is not clean: the check is marked partial.
			if container.Error != "" {
				container.Error += "; "
			}
			container.Error += "Libraries not checked: " + libs.Error
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
			f.Container, f.Image = container.Name, container.Image
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
	container.Vulnerabilities = nil
	for _, item := range findings {
		if item.fixable || item.exploited {
			toFix = append(toFix, item.finding)
		}
		if len(container.Vulnerabilities) < maxContainerVulnerabilities {
			container.Vulnerabilities = append(container.Vulnerabilities, item.finding)
		}
	}
	if len(findings) > maxContainerVulnerabilities {
		container.Notes = append(container.Notes, fmt.Sprintf("Only the %d most urgent of %d vulnerabilities are kept.", maxContainerVulnerabilities, len(findings)))
	}
	// The dashboard lists Vulnerabilities; Findings is kept, cut short, for
	// the flat list and older dashboards.
	if len(toFix) > maxContainerFindings {
		toFix = toFix[:maxContainerFindings]
	}
	container.Findings = toFix
	return findings, packages
}

// EndOfLifeRule is the finding for a container or image whose release has
// ended (lifecycle.RetiredRelease).
const EndOfLifeRule = "DG-EOL-001"

// packageCount counts the packages in a container's package database.
func packageCount(inventory *containers.Inventory) int {
	switch {
	case inventory.DPKGStatus != "":
		return strings.Count("\n"+inventory.DPKGStatus, "\nPackage: ")
	case inventory.APKInstalled != "":
		return strings.Count("\n"+inventory.APKInstalled, "\nP:")
	case inventory.RPMQuery != "":
		count := 0
		for _, line := range strings.Split(inventory.RPMQuery, "\n") {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count
	}
	return 0
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
