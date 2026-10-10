// Package checks implements the optional host checks that run alongside the
// package vulnerability scan: file integrity, malware indicators, security
// configuration, ClamAV, and the advanced scan with YARA-X. Every command is a fixed, read-only string
// defined here; nothing from the user or the host is interpolated into it.
package checks

import (
	"fmt"
	"strings"
	"time"

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
		ID: Antivirus, Name: "Antivirus scan", Sudo: "recommended",
		Description: "Scans temporary, home, and application directories for malware. Basic runs ClamAV, which the install script sets up; Advanced adds YARA rules.",
		Warning:     "ClamAV loads its signatures on the host, using about 1 GB of memory, and can take several minutes.",
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
}

type Result struct {
	Status     string    `json:"status"`
	Privileged bool      `json:"privileged"`
	Summary    string    `json:"summary"`
	Notes      []string  `json:"notes"`
	Error      string    `json:"error,omitempty"`
	Findings   []Finding `json:"findings"`
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

// Inputs carries what some checks need besides the host: the YARA rules.
type Inputs struct {
	YARA YARAInput
}

// Run executes one check. The package check is run by the scan itself.
func Run(id string, executor *Executor, target platform.Platform, now time.Time, inputs Inputs) Result {
	var result Result
	switch id {
	case Integrity:
		result = runIntegrity(executor, target)
	case Malware:
		result = runMalware(executor)
	case Config:
		result = runConfig(executor, target)
	case Antivirus:
		result = runAntivirus(executor, now)
	case YARA:
		result = runYARA(executor, inputs.YARA)
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
