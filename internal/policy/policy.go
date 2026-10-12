// Package policy lets admins add their own controls to audits, written in
// YAML. A policy can only test the settings the hardening audit already
// reads (SSH and kernel settings, login.defs, packages, services, mounts,
// listening ports and the permissions of key files), so it can never make an
// agent run a command or read anything new.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"deaconguard/internal/checks"
)

// Policy is a named set of controls.
type Policy struct {
	Name        string    `yaml:"name" json:"name"`
	Description string    `yaml:"description" json:"description"`
	Controls    []Control `yaml:"controls" json:"controls"`
}

// Control is one rule; exactly one of its checks is set.
type Control struct {
	ID          string `yaml:"id" json:"id"`
	Title       string `yaml:"title" json:"title"`
	Severity    string `yaml:"severity" json:"severity"`
	Rationale   string `yaml:"rationale" json:"rationale"`
	Remediation string `yaml:"remediation" json:"remediation"`
	Check       Check  `yaml:"check" json:"check"`
}

// Check is what a control tests.
type Check struct {
	SSHD      *Setting      `yaml:"sshd,omitempty" json:"sshd,omitempty"`
	Sysctl    *Setting      `yaml:"sysctl,omitempty" json:"sysctl,omitempty"`
	LoginDefs *Setting      `yaml:"login_defs,omitempty" json:"login_defs,omitempty"`
	Package   *PackageCheck `yaml:"package,omitempty" json:"package,omitempty"`
	Service   *ServiceCheck `yaml:"service,omitempty" json:"service,omitempty"`
	Mount     *MountCheck   `yaml:"mount,omitempty" json:"mount,omitempty"`
	Port      *PortCheck    `yaml:"port,omitempty" json:"port,omitempty"`
	File      *FileCheck    `yaml:"file,omitempty" json:"file,omitempty"`
}

// Setting compares a named setting: with one of the values in Is, or as a
// number with AtMost and AtLeast.
type Setting struct {
	Setting string   `yaml:"setting" json:"setting"`
	Is      []string `yaml:"is,omitempty" json:"is,omitempty"`
	AtMost  *int     `yaml:"at_most,omitempty" json:"at_most,omitempty"`
	AtLeast *int     `yaml:"at_least,omitempty" json:"at_least,omitempty"`
}

type PackageCheck struct {
	Name      string `yaml:"name" json:"name"`
	Installed bool   `yaml:"installed" json:"installed"`
}

type ServiceCheck struct {
	Name    string `yaml:"name" json:"name"`
	Running bool   `yaml:"running" json:"running"`
}

type MountCheck struct {
	Path    string   `yaml:"path" json:"path"`
	Options []string `yaml:"options" json:"options"`
}

// PortCheck: Listening false requires nothing on the port; Exposed false
// allows it only on a local address.
type PortCheck struct {
	Port      int    `yaml:"port" json:"port"`
	Protocol  string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Listening *bool  `yaml:"listening,omitempty" json:"listening,omitempty"`
	Exposed   *bool  `yaml:"exposed,omitempty" json:"exposed,omitempty"`
}

// FileCheck tests one of the key files the audit reads permissions of.
type FileCheck struct {
	Path       string `yaml:"path" json:"path"`
	ModeAtMost string `yaml:"mode_at_most,omitempty" json:"mode_at_most,omitempty"`
	Owner      string `yaml:"owner,omitempty" json:"owner,omitempty"`
}

// Files are the paths a FileCheck may name: the ones the audit reads.
var Files = []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/ssh/sshd_config", "/etc/crontab",
	"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"}

var (
	idPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,31}$`)
	severities = []string{"critical", "high", "medium", "low"}
)

// MaxBytes bounds a policy's YAML.
const MaxBytes = 64 << 10

// Parse reads and checks a policy. Errors say where the problem is.
func Parse(source []byte) (Policy, error) {
	if len(source) > MaxBytes {
		return Policy{}, fmt.Errorf("a policy is at most %d KB", MaxBytes>>10)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	decoder.KnownFields(true)
	var parsed Policy
	if err := decoder.Decode(&parsed); err != nil {
		return Policy{}, fmt.Errorf("the YAML could not be read: %w", err)
	}
	parsed.Name = strings.TrimSpace(parsed.Name)
	if parsed.Name == "" || len(parsed.Name) > 80 {
		return Policy{}, errors.New("give the policy a name of up to 80 characters")
	}
	if len(parsed.Controls) == 0 || len(parsed.Controls) > 200 {
		return Policy{}, errors.New("a policy has 1 to 200 controls")
	}
	baseline := map[string]bool{}
	for _, id := range checks.BaselineIDs() {
		baseline[id] = true
	}
	seen := map[string]bool{}
	for index, control := range parsed.Controls {
		where := fmt.Sprintf("control %d (%s)", index+1, control.ID)
		if !idPattern.MatchString(control.ID) {
			return Policy{}, fmt.Errorf("control %d: the id must start with a letter and use letters, digits, - _ or . (up to 32)", index+1)
		}
		if baseline[control.ID] {
			return Policy{}, fmt.Errorf("%s: %s is a baseline control; choose another id, such as ACME-01", where, control.ID)
		}
		if seen[control.ID] {
			return Policy{}, fmt.Errorf("%s: the id is used twice", where)
		}
		seen[control.ID] = true
		if strings.TrimSpace(control.Title) == "" {
			return Policy{}, fmt.Errorf("%s: give it a title", where)
		}
		parsed.Controls[index].Severity = strings.ToLower(control.Severity)
		if !slices.Contains(severities, parsed.Controls[index].Severity) {
			return Policy{}, fmt.Errorf("%s: severity must be critical, high, medium or low", where)
		}
		if err := validate(control.Check); err != nil {
			return Policy{}, fmt.Errorf("%s: %w", where, err)
		}
	}
	return parsed, nil
}

func validate(check Check) error {
	set := 0
	for _, present := range []bool{check.SSHD != nil, check.Sysctl != nil, check.LoginDefs != nil, check.Package != nil,
		check.Service != nil, check.Mount != nil, check.Port != nil, check.File != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return errors.New("its check needs exactly one of sshd, sysctl, login_defs, package, service, mount, port or file")
	}
	for _, setting := range []*Setting{check.SSHD, check.Sysctl, check.LoginDefs} {
		if setting == nil {
			continue
		}
		if setting.Setting == "" {
			return errors.New("name the setting")
		}
		if len(setting.Is) == 0 && setting.AtMost == nil && setting.AtLeast == nil {
			return errors.New("give is, at_most or at_least")
		}
	}
	switch {
	case check.Package != nil && check.Package.Name == "":
		return errors.New("name the package")
	case check.Service != nil && check.Service.Name == "":
		return errors.New("name the service")
	case check.Mount != nil && (check.Mount.Path == "" || len(check.Mount.Options) == 0):
		return errors.New("give the mount's path and options")
	case check.Port != nil && (check.Port.Port < 1 || check.Port.Port > 65535 || (check.Port.Listening == nil && check.Port.Exposed == nil)):
		return errors.New("give a port from 1 to 65535 and listening or exposed")
	case check.Port != nil && check.Port.Protocol != "" && check.Port.Protocol != "tcp" && check.Port.Protocol != "udp":
		return errors.New("protocol is tcp or udp")
	case check.File != nil && !slices.Contains(Files, check.File.Path):
		return fmt.Errorf("file checks can name only the files the audit reads: %s", strings.Join(Files, ", "))
	case check.File != nil && check.File.ModeAtMost == "" && check.File.Owner == "":
		return errors.New("give mode_at_most or owner")
	case check.File != nil && check.File.ModeAtMost != "":
		if _, err := strconv.ParseUint(check.File.ModeAtMost, 8, 32); err != nil {
			return errors.New("mode_at_most is an octal mode such as \"0640\"")
		}
	}
	return nil
}

// Evaluate runs a policy's controls against what an audit read. Without
// facts (an agent older than 0.14), every control is not checked.
func Evaluate(p Policy, facts *checks.Facts, listening []checks.Listening) []checks.ControlResult {
	results := make([]checks.ControlResult, 0, len(p.Controls))
	for _, control := range p.Controls {
		result := checks.ControlResult{ID: control.ID, Category: p.Name, Title: control.Title, Severity: control.Severity,
			Rationale: control.Rationale, Remediation: control.Remediation}
		if facts == nil {
			result.Status, result.Evidence = checks.ControlUnknown, "this audit has no settings to test; the agent needs DeaconGuard 0.14.0 or later"
		} else {
			result.Status, result.Evidence = run(control.Check, facts, listening)
		}
		results = append(results, result)
	}
	return results
}

func outcome(ok bool, format string, arguments ...any) (string, string) {
	if ok {
		return checks.ControlPass, fmt.Sprintf(format, arguments...)
	}
	return checks.ControlFail, fmt.Sprintf(format, arguments...)
}

func run(check Check, facts *checks.Facts, listening []checks.Listening) (string, string) {
	switch {
	case check.SSHD != nil:
		if len(facts.SSHD) == 0 {
			return checks.ControlNA, "no SSH server is installed"
		}
		return compare("sshd", check.SSHD, facts.SSHD, true)
	case check.Sysctl != nil:
		return compare("sysctl", check.Sysctl, facts.Sysctl, false)
	case check.LoginDefs != nil:
		return compare("login.defs", check.LoginDefs, facts.LoginDefs, true)
	case check.Package != nil:
		installed := slices.Contains(facts.Packages, check.Package.Name)
		state := map[bool]string{true: "installed", false: "not installed"}[installed]
		return outcome(installed == check.Package.Installed, "%s is %s", check.Package.Name, state)
	case check.Service != nil:
		name := strings.TrimSuffix(check.Service.Name, ".service")
		running := slices.Contains(facts.Active, name)
		state := map[bool]string{true: "running", false: "not running"}[running]
		return outcome(running == check.Service.Running, "%s is %s", name, state)
	case check.Mount != nil:
		options, mounted := facts.Mounts[check.Mount.Path]
		if !mounted {
			return checks.ControlFail, check.Mount.Path + " is not a separate mount"
		}
		var missing []string
		for _, option := range check.Mount.Options {
			if !slices.Contains(options, option) {
				missing = append(missing, option)
			}
		}
		return outcome(len(missing) == 0, "%s is mounted with %s", check.Mount.Path, strings.Join(options, ","))
	case check.Port != nil:
		var found []checks.Listening
		for _, socket := range listening {
			if socket.Port == check.Port.Port && (check.Port.Protocol == "" || socket.Protocol == check.Port.Protocol) {
				found = append(found, socket)
			}
		}
		if check.Port.Listening != nil && !*check.Port.Listening {
			return outcome(len(found) == 0, "port %d: %d listening sockets", check.Port.Port, len(found))
		}
		if check.Port.Listening != nil && *check.Port.Listening && len(found) == 0 {
			return checks.ControlFail, fmt.Sprintf("nothing listens on port %d", check.Port.Port)
		}
		if check.Port.Exposed != nil && !*check.Port.Exposed {
			for _, socket := range found {
				if socket.Exposed {
					return checks.ControlFail, fmt.Sprintf("port %d listens on all interfaces", check.Port.Port)
				}
			}
		}
		return checks.ControlPass, fmt.Sprintf("port %d: %d listening sockets, none on all interfaces", check.Port.Port, len(found))
	case check.File != nil:
		mode, found := facts.Modes[check.File.Path]
		if !found {
			return checks.ControlNA, check.File.Path + " does not exist"
		}
		if check.File.ModeAtMost != "" {
			limit, _ := strconv.ParseUint(check.File.ModeAtMost, 8, 32)
			actual, _ := strconv.ParseUint(mode.Mode, 8, 32)
			if actual&^limit != 0 {
				return checks.ControlFail, fmt.Sprintf("%s is %s (at most %s)", check.File.Path, mode.Mode, check.File.ModeAtMost)
			}
		}
		if check.File.Owner != "" && mode.Owner != check.File.Owner {
			return checks.ControlFail, fmt.Sprintf("%s is owned by %s (expected %s)", check.File.Path, mode.Owner, check.File.Owner)
		}
		return checks.ControlPass, fmt.Sprintf("%s is %s, owned by %s:%s", check.File.Path, mode.Mode, mode.Owner, mode.Group)
	}
	return checks.ControlUnknown, "no check"
}

// compare tests a setting; caseless compares values ignoring case.
func compare(source string, setting *Setting, values map[string]string, caseless bool) (string, string) {
	key := setting.Setting
	if caseless {
		key = strings.ToLower(key)
	}
	value, set := values[key]
	if !set {
		return checks.ControlFail, fmt.Sprintf("%s %s is not set", source, setting.Setting)
	}
	if len(setting.Is) > 0 {
		for _, want := range setting.Is {
			if value == want || (caseless && strings.EqualFold(value, want)) {
				return checks.ControlPass, fmt.Sprintf("%s %s = %s", source, setting.Setting, value)
			}
		}
		return checks.ControlFail, fmt.Sprintf("%s %s = %s (expected %s)", source, setting.Setting, value, strings.Join(setting.Is, " or "))
	}
	number, err := strconv.Atoi(strings.Fields(value + " x")[0])
	if err != nil {
		return checks.ControlFail, fmt.Sprintf("%s %s = %s, which is not a number", source, setting.Setting, value)
	}
	if setting.AtMost != nil && number > *setting.AtMost {
		return checks.ControlFail, fmt.Sprintf("%s %s = %d (at most %d)", source, setting.Setting, number, *setting.AtMost)
	}
	if setting.AtLeast != nil && number < *setting.AtLeast {
		return checks.ControlFail, fmt.Sprintf("%s %s = %d (at least %d)", source, setting.Setting, number, *setting.AtLeast)
	}
	return checks.ControlPass, fmt.Sprintf("%s %s = %d", source, setting.Setting, number)
}

// Example is a starting point admins can adapt.
const Example = `name: Acme server policy
description: Settings Acme requires on every server, beyond the baseline.
controls:
  - id: ACME-01
    title: Root can't log in over SSH at all
    severity: high
    rationale: Admins sign in as themselves and use sudo, so every action is attributed.
    remediation: Set PermitRootLogin no in /etc/ssh/sshd_config.
    check:
      sshd: { setting: PermitRootLogin, is: ["no"] }
  - id: ACME-02
    title: Passwords expire within 90 days
    severity: medium
    remediation: Set PASS_MAX_DAYS 90 in /etc/login.defs.
    check:
      login_defs: { setting: PASS_MAX_DAYS, at_most: 90 }
  - id: ACME-03
    title: The monitoring agent is running
    severity: medium
    remediation: systemctl enable --now node_exporter
    check:
      service: { name: node_exporter, running: true }
  - id: ACME-04
    title: Telnet is not installed
    severity: high
    check:
      package: { name: telnet, installed: false }
  - id: ACME-05
    title: MySQL only listens locally
    severity: high
    check:
      port: { port: 3306, exposed: false }
`
