package checks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"deaconguard/internal/platform"
)

// Hardening is the audit's settings check against the DeaconGuard Linux
// baseline: accounts, SSH, kernel and network settings, services, logging,
// file permissions, updates and time.
const Hardening = "hardening"

// Control statuses.
const (
	ControlPass = "pass"
	ControlFail = "fail"
	// ControlNA: the control does not apply to this machine.
	ControlNA = "na"
	// ControlUnknown: the evidence could not be read, usually without root.
	ControlUnknown = "unknown"
)

// ControlResult is one baseline control's outcome on a machine.
type ControlResult struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation"`
}

// Inventory describes the machine for the audit report.
type Inventory struct {
	Hostname       string      `json:"hostname"`
	OS             string      `json:"os"`
	Kernel         string      `json:"kernel"`
	Architecture   string      `json:"architecture"`
	UptimeSeconds  int64       `json:"uptime_seconds"`
	Virtualization string      `json:"virtualization"`
	CPUs           int         `json:"cpus"`
	MemoryBytes    int64       `json:"memory_bytes"`
	Disks          []Disk      `json:"disks"`
	Addresses      []string    `json:"addresses"`
	Packages       int         `json:"packages"`
	Listening      []Listening `json:"listening"`
	LoginUsers     []string    `json:"login_users"`
	Administrators []string    `json:"administrators"`
	Timezone       string      `json:"timezone"`
	TimeSynced     bool        `json:"time_synced"`
}

type Disk struct {
	Mount       string `json:"mount"`
	SizeBytes   int64  `json:"size_bytes"`
	UsedBytes   int64  `json:"used_bytes"`
	UsedPercent int    `json:"used_percent"`
}

type Listening struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	// Exposed: bound to every interface, so other machines can connect.
	Exposed bool `json:"exposed"`
}

// machine holds the facts the controls read.
type machine struct {
	family     platform.Family
	facts      map[string]string
	root       bool // the root facts were collected with root
	packages   map[string]bool
	sysctl     map[string]string
	sshd       map[string]string
	sshdSource string
	active     map[string]bool
	modes      map[string]fileMode
}

type fileMode struct {
	mode         int
	owner, group string
}

func runHardening(executor *Executor, target platform.Platform) Result {
	var result Result
	output, _, err := executor.Run(script(userFacts), 8<<20, factsTimeout)
	if err != nil {
		return failed(fmt.Errorf("read the machine's settings: %w", err))
	}
	facts := sections(output)
	privileged := executor.Privileged()
	if privileged {
		rootOutput, _, _, err := executor.RunPrivileged(script(rootFacts), 8<<20, factsTimeout)
		if err != nil {
			result.note("Settings that need root could not be read: %s", truncate(err.Error(), 160))
			privileged = false
		} else {
			for name, value := range sections(rootOutput) {
				facts[name] = value
			}
		}
	}
	if !privileged {
		result.note("Settings that need root, such as password files, the firewall and file permissions across the disk, were not checked. Run the audit with root for a complete result.")
	}
	m := newMachine(target.Family, facts, privileged)
	result.Inventory = m.inventory(target)
	result.Facts = m.export()
	for _, control := range baseline {
		outcome := ControlResult{
			ID: control.id, Category: control.category, Title: control.title, Severity: control.severity,
			Rationale: control.rationale, Remediation: control.remediation,
		}
		outcome.Status, outcome.Evidence = control.check(m)
		result.Controls = append(result.Controls, outcome)
		if outcome.Status == ControlFail {
			result.add(Finding{Rule: "hardening." + control.id, Severity: strings.ToUpper(control.severity), Title: control.title,
				Detail: control.rationale + " " + control.remediation, Evidence: outcome.Evidence})
		}
	}
	result.Privileged = privileged
	failedCount, passed := 0, 0
	for _, control := range result.Controls {
		switch control.Status {
		case ControlFail:
			failedCount++
		case ControlPass:
			passed++
		}
	}
	result.Summary = fmt.Sprintf("%d of %d controls passed", passed, passed+failedCount)
	partial := !privileged
	return result.finish(partial)
}

func newMachine(family platform.Family, facts map[string]string, root bool) *machine {
	m := &machine{family: family, facts: facts, root: root, packages: map[string]bool{}, sysctl: map[string]string{},
		active: map[string]bool{}, modes: map[string]fileMode{}}
	for _, line := range lines([]byte(facts["packages"])) {
		m.packages[strings.TrimSpace(line)] = true
	}
	for _, line := range lines([]byte(facts["sysctl"])) {
		if key, value, found := strings.Cut(line, "="); found {
			m.sysctl[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	for _, line := range lines([]byte(facts["active-units"])) {
		if fields := strings.Fields(line); len(fields) > 0 {
			m.active[strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(fields[0], ".service"), ".socket"), ".timer")] = true
		}
	}
	for _, line := range lines([]byte(facts["modes"])) {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			continue
		}
		mode, err := strconv.ParseInt(fields[0], 8, 32)
		if err == nil {
			m.modes[fields[3]] = fileMode{mode: int(mode), owner: fields[1], group: fields[2]}
		}
	}
	// sshd -T, run as root, prints the settings sshd really uses; without
	// it, the configuration files are read with OpenSSH's defaults.
	if effective := facts["sshd-effective"]; root && strings.TrimSpace(effective) != "" {
		m.sshd, m.sshdSource = map[string]string{}, "sshd -T"
		for _, line := range lines([]byte(effective)) {
			if key, value, found := strings.Cut(strings.TrimSpace(line), " "); found {
				m.sshd[strings.ToLower(key)] = strings.ToLower(strings.TrimSpace(value))
			}
		}
	} else if files := facts["sshd-files"]; strings.TrimSpace(files) != "" {
		m.sshd, m.sshdSource = effectiveSSHD([]byte(files)), "the SSH configuration files"
		for key, value := range sshdDefaults {
			if _, set := m.sshd[key]; !set {
				m.sshd[key] = value
			}
		}
	}
	return m
}

// sshdDefaults are OpenSSH's built-in values, which apply when the
// configuration files leave a setting out.
var sshdDefaults = map[string]string{
	"permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "permitemptypasswords": "no",
	"x11forwarding": "no", "maxauthtries": "6", "clientaliveinterval": "0", "hostbasedauthentication": "no",
	"ignorerhosts": "yes", "logingracetime": "120", "permituserenvironment": "no", "banner": "none", "loglevel": "info",
}

func (m *machine) collected(name string) bool {
	_, ok := m.facts[name]
	return ok
}

func (m *machine) installed(names ...string) []string {
	var found []string
	for _, name := range names {
		if m.packages[name] {
			found = append(found, name)
		}
	}
	return found
}

func (m *machine) anyActive(names ...string) string {
	for _, name := range names {
		if m.active[name] {
			return name
		}
	}
	return ""
}

// keyValues reads "KEY value" or "key = value" lines, ignoring comments.
func keyValues(text string) map[string]string {
	values := make(map[string]string)
	for _, line := range lines([]byte(text)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			key, value = fields[0], strings.Join(fields[1:], " ")
		}
		values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return values
}

// passwdEntry is one line of /etc/passwd.
type passwdEntry struct {
	name  string
	uid   int
	shell string
}

func (m *machine) passwd() []passwdEntry {
	var entries []passwdEntry
	for _, line := range lines([]byte(m.facts["passwd"])) {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		entries = append(entries, passwdEntry{name: fields[0], uid: uid, shell: fields[6]})
	}
	return entries
}

func loginShell(shell string) bool {
	return shell != "" && !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false") &&
		!strings.HasSuffix(shell, "/sync") && !strings.HasSuffix(shell, "/shutdown") && !strings.HasSuffix(shell, "/halt")
}

func (m *machine) inventory(target platform.Platform) *Inventory {
	inventory := &Inventory{OS: strings.TrimSpace(m.facts["os"]), Hostname: strings.TrimSpace(m.facts["hostname"]),
		Virtualization: strings.TrimSpace(m.facts["virtualization"]), Packages: len(m.packages)}
	if fields := strings.Fields(m.facts["uname"]); len(fields) >= 3 {
		inventory.Kernel, inventory.Architecture = fields[0]+" "+fields[1], fields[2]
	}
	if fields := strings.Fields(m.facts["uptime"]); len(fields) > 0 {
		if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
			inventory.UptimeSeconds = int64(seconds)
		}
	}
	inventory.CPUs, _ = strconv.Atoi(strings.TrimSpace(m.facts["cpus"]))
	if fields := strings.Fields(m.facts["memory"]); len(fields) >= 2 {
		if kilobytes, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			inventory.MemoryBytes = kilobytes * 1024
		}
	}
	for index, line := range lines([]byte(m.facts["disks"])) {
		fields := strings.Fields(line)
		if index == 0 || len(fields) < 6 {
			continue
		}
		size, _ := strconv.ParseInt(fields[1], 10, 64)
		used, _ := strconv.ParseInt(fields[2], 10, 64)
		percent, _ := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		inventory.Disks = append(inventory.Disks, Disk{Mount: fields[5], SizeBytes: size * 1024, UsedBytes: used * 1024, UsedPercent: percent})
	}
	for _, line := range lines([]byte(m.facts["addresses"])) {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "lo" {
			continue
		}
		name, _, _ := strings.Cut(fields[0], "@")
		for _, address := range fields[2:] {
			if !strings.HasPrefix(address, "fe80:") {
				inventory.Addresses = append(inventory.Addresses, name+" "+address)
			}
		}
	}
	inventory.Listening = listening(m.facts["listening"])
	for _, entry := range m.passwd() {
		if (entry.uid == 0 || entry.uid >= 1000) && loginShell(entry.shell) && entry.name != "nobody" {
			inventory.LoginUsers = append(inventory.LoginUsers, entry.name)
		}
	}
	admins := map[string]bool{}
	for _, line := range lines([]byte(m.facts["admins"])) {
		fields := strings.Split(line, ":")
		if len(fields) == 4 && fields[3] != "" {
			for _, name := range strings.Split(fields[3], ",") {
				admins[name] = true
			}
		}
	}
	for name := range admins {
		inventory.Administrators = append(inventory.Administrators, name)
	}
	sort.Strings(inventory.Administrators)
	clock := keyValues(m.facts["time"])
	inventory.Timezone = clock["timezone"]
	inventory.TimeSynced = clock["ntpsynchronized"] == "yes"
	return inventory
}

// listening parses ss or netstat output into sockets, one per protocol and port.
func listening(output string) []Listening {
	seen := map[string]bool{}
	var sockets []Listening
	for _, line := range lines([]byte(output)) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !(strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp")) {
			continue
		}
		local := ""
		for index, field := range fields {
			if index > 0 && strings.Contains(field, ":") {
				local = field
				break
			}
		}
		separator := strings.LastIndex(local, ":")
		if separator < 0 {
			continue
		}
		port, err := strconv.Atoi(local[separator+1:])
		if err != nil {
			continue
		}
		host, _, _ := strings.Cut(strings.Trim(local[:separator], "[]"), "%")
		protocol := fields[0][:3]
		exposed := host == "*" || host == "0.0.0.0" || host == "::" || host == ""
		key := fmt.Sprintf("%s/%s/%d", protocol, host, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		sockets = append(sockets, Listening{Protocol: protocol, Address: host, Port: port, Exposed: exposed})
	}
	sort.Slice(sockets, func(a, b int) bool {
		if sockets[a].Port != sockets[b].Port {
			return sockets[a].Port < sockets[b].Port
		}
		return sockets[a].Protocol < sockets[b].Protocol
	})
	return sockets
}

// Facts are the settings custom policies can test: no file contents beyond
// these, and nothing from /etc/shadow.
type Facts struct {
	// SSHD is the SSH server's effective settings, lowercase; empty without
	// an SSH server.
	SSHD map[string]string `json:"sshd,omitempty"`
	// Root says whether facts that need root were read.
	Root      bool                `json:"root"`
	Sysctl    map[string]string   `json:"sysctl"`
	LoginDefs map[string]string   `json:"login_defs"`
	Packages  []string            `json:"packages"`
	Active    []string            `json:"active"`
	Mounts    map[string][]string `json:"mounts"`
	Modes     map[string]FileMode `json:"modes"`
}

// FileMode is a key file's permissions, such as "0640", and owners.
type FileMode struct {
	Mode  string `json:"mode"`
	Owner string `json:"owner"`
	Group string `json:"group"`
}

func (m *machine) export() *Facts {
	facts := &Facts{SSHD: m.sshd, Root: m.root, Sysctl: m.sysctl, LoginDefs: keyValues(m.facts["login.defs"]),
		Mounts: map[string][]string{}, Modes: map[string]FileMode{}}
	for name := range m.packages {
		if name != "" {
			facts.Packages = append(facts.Packages, name)
		}
	}
	sort.Strings(facts.Packages)
	for name := range m.active {
		facts.Active = append(facts.Active, name)
	}
	sort.Strings(facts.Active)
	for _, line := range lines([]byte(m.facts["mounts"])) {
		if fields := strings.Fields(line); len(fields) >= 4 {
			facts.Mounts[fields[1]] = strings.Split(fields[3], ",")
		}
	}
	for path, mode := range m.modes {
		facts.Modes[path] = FileMode{Mode: fmt.Sprintf("%04o", mode.mode), Owner: mode.owner, Group: mode.group}
	}
	return facts
}
