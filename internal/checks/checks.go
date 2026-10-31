// Package checks implements the optional host checks that run alongside the
// package vulnerability scan: file integrity, malware indicators, security
// configuration, the hardening audit, application libraries, ClamAV, and the advanced scan with YARA-X. Every command is a fixed, read-only string
// defined here; nothing from the user or the host is interpolated into it.
package checks

import (
	"deaconguard/internal/containers"
	"fmt"
	"strings"
	"time"

	"deaconguard/internal/libraries"
	"deaconguard/internal/platform"
)

const (
	Packages  = "packages"
	Integrity = "integrity"
	Malware   = "malware"
	Config    = "config"
	Antivirus = "antivirus"
	// YARA is the advanced antivirus scan. It always runs with Antivirus.
	YARA = "yara"
	// Kubernetes checks a cluster through its API; only a cluster agent,
	// enrolled from inside the cluster, runs it, and it runs alone.
	Kubernetes = "kubernetes"
)

const (
	StatusCompleted = "completed"
	// StatusPartial means some evidence could not be read, usually for lack of sudo.
	StatusPartial = "partial"
	StatusSkipped = "skipped"
	StatusFailed  = "failed"
)

// maxFindings bounds how many findings one check reports; the rest are counted in a note.
const maxFindings = 200

type Definition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Sudo is "none" when the check needs no privileges, or "recommended"
	// when it can see more with sudo.
	Sudo    string `json:"sudo"`
	Default bool   `json:"default"`
	Warning string `json:"warning,omitempty"`
}

var definitions = []Definition{
	{
		ID: Packages, Name: "Package vulnerabilities", Sudo: "none", Default: true,
		Description: "Installed packages and the running kernel compared with the distribution's official security advisories.",
	},
	{
		ID: Libraries, Name: "Application libraries", Sudo: "recommended",
		Description: "Finds the libraries applications use (npm, Python, Go, Ruby, Rust and PHP) and checks them against the OSV vulnerability database. The server sends OSV only the libraries' names and versions.",
	},
	{
		ID: Containers, Name: "Running containers", Sudo: "recommended",
		Description: "Finds the containers running on the host (Docker, Podman, containerd) and checks each one's OS packages and application libraries, as for the host itself. Nothing inside a container is run.",
	},
	{
		ID: Integrity, Name: "System file integrity", Sudo: "recommended",
		Description: "Verifies installed system files against the package manager's checksums to find replaced binaries and libraries.",
		Warning:     "Reads every packaged file on the host, which can take several minutes.",
	},
	{
		ID: Malware, Name: "Malware & compromise indicators", Sudo: "recommended",
		Description: "Looks for crypto miners, processes running from temporary or deleted files, preloaded libraries, and suspicious cron or systemd persistence.",
	},
	{
		ID: Config, Name: "Security configuration", Sudo: "recommended",
		Description: "Checks SSH server settings, services listening on all interfaces, pending reboots, automatic updates, and the host firewall.",
	},
	{
		ID: Hardening, Name: "Hardening audit", Sudo: "recommended",
		Description: "Checks about 60 security settings against the DeaconGuard Linux baseline: accounts and passwords, SSH, network and kernel settings, services and the firewall, logging, file permissions, updates and time. Also records the machine's inventory.",
	},
	{
		ID: Changes, Name: "Host changes", Sudo: "recommended",
		Description: "Records the ports open to the network, login accounts, administrators and sudoers rules, SSH keys, enabled services and scheduled jobs, and reports what changed since the previous scan. Takes a few seconds.",
	},
	{
		ID: Antivirus, Name: "Antivirus scan", Sudo: "recommended",
		Description: "Scans temporary, home, and application directories for malware. Basic runs ClamAV, which the install script sets up; Advanced adds YARA rules.",
		Warning:     "ClamAV loads its signatures on the host, using about 1 GB of memory, and can take several minutes.",
	},
	{
		ID: Kubernetes, Name: "Kubernetes cluster", Sudo: "none",
		Description: "Checks a Kubernetes cluster through its API, read-only: workloads, RBAC, namespaces without network policies or Pod Security Standards, the Kubernetes version and its CVEs, and the API server's settings. Runs on clusters enrolled with the cluster agent.",
	},
	{
		ID: YARA, Name: "Advanced antivirus scan (YARA)", Sudo: "recommended",
		Description: "Adds YARA-X with the YARA Forge core rules to the antivirus scan, for webshells, crypto miners, backdoors, and attacker tools that signature scanners often miss. Always runs together with ClamAV.",
		Warning:     "Reads the same directories as ClamAV again, which can take several more minutes.",
	},
}

// Definitions lists the available checks in display order.
func Definitions() []Definition { return append([]Definition(nil), definitions...) }

// Normalize validates check IDs and returns them in display order without duplicates.
func Normalize(ids []string) ([]string, error) {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		known := false
		for _, definition := range definitions {
			known = known || definition.ID == id
		}
		if !known {
			return nil, fmt.Errorf("unknown check %q", id)
		}
		wanted[id] = true
	}
	// The advanced antivirus scan adds YARA to ClamAV; it never replaces it.
	if wanted[YARA] {
		wanted[Antivirus] = true
	}
	ordered := make([]string, 0, len(wanted))
	for _, definition := range definitions {
		if wanted[definition.ID] {
			ordered = append(ordered, definition.ID)
		}
	}
	if len(ordered) == 0 {
		return nil, fmt.Errorf("choose at least one check")
	}
	return ordered, nil
}

type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`

	// The rest are set on vulnerabilities in libraries, containers and
	// images, so the dashboard can group them: the container and image it
	// is in, whether it is in an OS package ("os") or an application
	// library ("library"), the package, its version and ecosystem, the
	// versions that fix it, and the files it was found in (inside the
	// container, for a container).
	Container string   `json:"container,omitempty"`
	Image     string   `json:"image,omitempty"`
	Source    string   `json:"source,omitempty"`
	Package   string   `json:"package,omitempty"`
	Version   string   `json:"version,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Fixed     string   `json:"fixed,omitempty"`
	Fixable   bool     `json:"fixable,omitempty"`
	Exploited bool     `json:"exploited,omitempty"`
	Paths     []string `json:"paths,omitempty"`
}

type Result struct {
	Status     string    `json:"status"`
	Privileged bool      `json:"privileged"`
	Summary    string    `json:"summary"`
	Notes      []string  `json:"notes"`
	Error      string    `json:"error,omitempty"`
	Findings   []Finding `json:"findings"`
	// Controls and Inventory are set by the hardening audit only.
	Controls  []ControlResult `json:"controls,omitempty"`
	Inventory *Inventory      `json:"inventory,omitempty"`
	// Facts are the settings the hardening audit read, for custom policies
	// the server evaluates.
	Facts *Facts `json:"facts,omitempty"`
	// Libraries is what the application library check found on the host;
	// the server checks it against OSV.
	Libraries *libraries.Result `json:"libraries,omitempty"`
	// Containers are the running containers, set by the container check.
	Containers []ContainerResult `json:"containers,omitempty"`
	// Cluster describes the cluster the Kubernetes check read.
	Cluster *Cluster `json:"cluster,omitempty"`
	// Snapshot is what the host change check recorded; the server compares
	// it with the previous one.
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Cluster is what the Kubernetes check read of a cluster.
type Cluster struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Nodes        int      `json:"nodes"`
	Architecture string   `json:"architecture,omitempty"`
	Namespaces   int      `json:"namespaces"`
	Workloads    int      `json:"workloads"`
	Images       []string `json:"images,omitempty"`
	// Running are the builds the pods run, from their status, with where;
	// empty from cluster agents before 1.20.0, which sent Images only.
	Running []RunningImage `json:"running_images,omitempty"`
}

// RunningImage is an image pods run: the reference in their spec, the
// digest of the build running, when the runtime reports one, and the
// namespaces and number of pods that run it.
type RunningImage struct {
	Image      string   `json:"image"`
	Digest     string   `json:"digest,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Pods       int      `json:"pods,omitempty"`
}

// ForHost leaves out the checks a kind of host doesn't run: a cluster runs
// only the Kubernetes check, a Mac the macOS checks, and a machine every
// check but Kubernetes. It returns nil when nothing is left.
func ForHost(kind string, ids []string) []string {
	var kept []string
	for _, id := range ids {
		switch kind {
		case "cluster":
			if id == Kubernetes {
				kept = append(kept, id)
			}
		case "mac":
			for _, mac := range MacOSChecks {
				if id == mac {
					kept = append(kept, id)
				}
			}
		default:
			if id != Kubernetes {
				kept = append(kept, id)
			}
		}
	}
	return kept
}

func (result *Result) add(finding Finding) {
	result.Findings = append(result.Findings, finding)
}

func (result *Result) note(format string, arguments ...any) {
	result.Notes = append(result.Notes, fmt.Sprintf(format, arguments...))
}

// finish caps the findings, fills in the summary, and picks a status.
func (result *Result) finish(partial bool) Result {
	if len(result.Findings) > maxFindings {
		result.note("%d more findings were not listed.", len(result.Findings)-maxFindings)
		result.Findings = result.Findings[:maxFindings]
	}
	if result.Findings == nil {
		result.Findings = []Finding{}
	}
	if result.Notes == nil {
		result.Notes = []string{}
	}
	if result.Status == "" {
		result.Status = StatusCompleted
		if partial {
			result.Status = StatusPartial
		}
	}
	if result.Summary == "" {
		switch len(result.Findings) {
		case 0:
			result.Summary = "No issues found"
		case 1:
			result.Summary = "1 issue found"
		default:
			result.Summary = fmt.Sprintf("%d issues found", len(result.Findings))
		}
	}
	return *result
}

// Inputs carries what some checks need besides the host: the YARA rules,
// and the running containers' own files for the malware checks.
type Inputs struct {
	YARA YARAInput
	// Containers are the running containers, with the folders of their
	// writable files; ContainersSkipped counts those whose folders couldn't
	// be found.
	Containers        []containers.Writable
	ContainersSkipped int
}

// Run executes one check. The package check is run by the scan itself.
func Run(id string, executor *Executor, target platform.Platform, now time.Time, inputs Inputs) Result {
	if target.Family == platform.MacOS {
		if id == Hardening {
			return runMacHardening(executor, target)
		}
		return macOSSkipped(id)
	}
	var result Result
	switch id {
	case Libraries:
		result = runLibraries(executor)
	case Integrity:
		result = runIntegrity(executor, target)
	case Malware:
		result = runMalware(executor, inputs)
	case Config:
		result = runConfig(executor, target)
	case Hardening:
		result = runHardening(executor, target)
	case Changes:
		result = runChanges(executor)
	case Antivirus:
		result = runAntivirus(executor, now, inputs)
	case YARA:
		result = runYARA(executor, inputs)
	default:
		return Result{Status: StatusFailed, Error: fmt.Sprintf("unknown check %q", id), Findings: []Finding{}, Notes: []string{}}
	}
	if note := executor.SudoNote(); note != "" && result.Status != StatusSkipped {
		result.Notes = append([]string{note}, result.Notes...)
	}
	return result
}

func failed(err error) Result {
	return Result{Status: StatusFailed, Error: err.Error(), Summary: "Check could not run", Findings: []Finding{}, Notes: []string{}}
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

func lines(output []byte) []string {
	result := make([]string, 0)
	for _, line := range strings.Split(string(output), "\n") {
		if line = strings.TrimRight(line, "\r"); strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}
