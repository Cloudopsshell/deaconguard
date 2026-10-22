package checks

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/platform"
)

// categoryMacProtection holds macOS's own protections: disk encryption,
// System Integrity Protection, Gatekeeper and XProtect.
const categoryMacProtection = "System protection"

// macPreferences are the preference files the macOS controls read, each as
// the local file and the one a configuration profile (MDM) installs, which
// wins. plutil turns them into XML whatever their format.
var macPreferences = []string{"com.apple.SoftwareUpdate", "com.apple.commerce", "com.apple.loginwindow", "com.apple.MCX"}

// macFacts are the fixed, read-only commands of the macOS audit. A few need
// root (systemsetup, and lsof for every process); without it those controls
// are reported as not checked.
func macFacts() []fact {
	facts := []fact{
		{"os", "sw_vers -productVersion; sw_vers -buildVersion"},
		{"uname", "uname -srm"},
		{"hostname", "hostname"},
		{"now", "date +%s"},
		{"boottime", "sysctl -n kern.boottime"},
		{"cpus", "sysctl -n hw.ncpu"},
		{"memory", "sysctl -n hw.memsize"},
		{"vmm", "sysctl -n kern.hv_vmm_present"},
		{"disks", "df -P -k / /System/Volumes/Data"},
		{"addresses", "ifconfig | grep -E '^[a-z]|inet6? '"},
		{"timezone", "readlink /etc/localtime"},
		{"filevault", "fdesetup status"},
		{"sip", "csrutil status"},
		{"gatekeeper", "spctl --status"},
		{"firewall", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"},
		{"stealth", "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"},
		{"launchd-disabled", "launchctl print-disabled system"},
		{"remote-login", "systemsetup -getremotelogin"},
		{"network-time", "systemsetup -getusingnetworktime"},
		{"xprotect", "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString; stat -f %m /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"},
		{"updates", "softwareupdate --list --no-scan 2>&1"},
		{"admins", "dscl . -read /Groups/admin GroupMembership"},
		{"users", "dscl . -list /Users UniqueID"},
		{"listening", "lsof -nP -iTCP -sTCP:LISTEN"},
	}
	for _, domain := range macPreferences {
		facts = append(facts,
			fact{"pref:" + domain, "plutil -convert xml1 -o - /Library/Preferences/" + domain + ".plist | head -c 1048576"},
			fact{"managed:" + domain, "plutil -convert xml1 -o - '/Library/Managed Preferences/" + domain + ".plist' | head -c 1048576"})
	}
	return facts
}

// plistTopLevel reads the top-level keys of an XML property list: booleans
// as "true" or "false", numbers and strings as written, and containers as
// "(array)" or "(dict)".
func plistTopLevel(document string) map[string]string {
	values := map[string]string{}
	decoder := xml.NewDecoder(strings.NewReader(document))
	decoder.Strict = false
	depth, key := 0, ""
	for {
		token, err := decoder.Token()
		if err == io.EOF || err != nil {
			return values
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			// <plist> is depth 1 and its <dict> depth 2; its keys and
			// values are depth 3.
			if depth != 3 {
				continue
			}
			name := element.Name.Local
			switch name {
			case "key":
				var text string
				if decoder.DecodeElement(&text, &element) == nil {
					key = text
				}
				depth--
			case "true", "false":
				if key != "" {
					values[key] = name
				}
				key = ""
			case "string", "integer", "real", "date":
				var text string
				if decoder.DecodeElement(&text, &element) == nil && key != "" {
					values[key] = strings.TrimSpace(text)
				}
				key = ""
				depth--
			case "array", "dict", "data":
				if key != "" {
					values[key] = "(" + name + ")"
				}
				key = ""
			}
		case xml.EndElement:
			depth--
		}
	}
}

// macMachine is what the macOS controls read.
type macMachine struct {
	facts   map[string]string
	root    bool
	prefs   map[string]map[string]string
	managed map[string]map[string]string
	now     time.Time
}

func newMacMachine(facts map[string]string, root bool, now time.Time) *macMachine {
	m := &macMachine{facts: facts, root: root, prefs: map[string]map[string]string{}, managed: map[string]map[string]string{}, now: now}
	for _, domain := range macPreferences {
		m.prefs[domain] = plistTopLevel(facts["pref:"+domain])
		m.managed[domain] = plistTopLevel(facts["managed:"+domain])
	}
	if seconds, err := strconv.ParseInt(strings.TrimSpace(facts["now"]), 10, 64); err == nil {
		m.now = time.Unix(seconds, 0)
	}
	return m
}

// setting is a preference as macOS applies it: the configuration profile's,
// else the local one, else ""; source says which.
func (m *macMachine) setting(domain, key string) (value, source string) {
	if value, ok := m.managed[domain][key]; ok {
		return value, "a configuration profile"
	}
	if value, ok := m.prefs[domain][key]; ok {
		return value, "local setting"
	}
	return "", ""
}

// enabledByDefault checks a switch that macOS turns on unless told otherwise.
func (m *macMachine) enabledByDefault(domain, key, what string) (string, string) {
	value, source := m.setting(domain, key)
	switch value {
	case "", "true", "1":
		if source == "" {
			return pass("%s: on (the macOS default; %s isn't set)", what, key)
		}
		return pass("%s: on (%s)", what, source)
	}
	return fail("%s: off (%s = %s, %s)", what, key, value, source)
}

// launchd reports a system service's state from `launchctl print-disabled
// system`: "enabled", "disabled", or "" when it isn't listed, which is its
// default.
func (m *macMachine) launchd(label string) string {
	pattern := regexp.MustCompile(`"` + regexp.QuoteMeta(label) + `"\s*=>\s*(\w+)`)
	match := pattern.FindStringSubmatch(m.facts["launchd-disabled"])
	if match == nil {
		return ""
	}
	switch match[1] {
	case "enabled", "false":
		return "enabled"
	}
	return "disabled"
}

var macBaseline = []struct {
	control
	check func(*macMachine) (string, string)
}{
	{control{id: "MACOS-01", category: categoryMacProtection, severity: "high", title: "FileVault encrypts the startup disk",
		rationale:   "Without FileVault, anyone holding the Mac, or its disk, can read everything on it.",
		remediation: "Turn on FileVault in System Settings → Privacy & Security → FileVault, and keep the recovery key somewhere safe, or escrow it with your MDM."},
		func(m *macMachine) (string, string) {
			status := strings.TrimSpace(m.facts["filevault"])
			switch {
			case strings.HasPrefix(status, "FileVault is On"):
				return pass("%s", status)
			case strings.HasPrefix(status, "FileVault is Off"):
				return fail("%s", status)
			}
			return unknown("fdesetup status: %s", truncate(status, 120))
		}},
	{control{id: "MACOS-02", category: categoryMacProtection, severity: "high", title: "System Integrity Protection is on",
		rationale:   "System Integrity Protection stops even root from changing macOS's own files and processes, which most malware needs to persist.",
		remediation: "Start the Mac in Recovery, open Terminal, run csrutil enable, and restart."},
		func(m *macMachine) (string, string) {
			status := strings.TrimSpace(m.facts["sip"])
			switch {
			case strings.Contains(status, "status: enabled"):
				return pass("%s", status)
			case strings.Contains(status, "status: disabled"), strings.Contains(status, "Custom Configuration"):
				return fail("%s", truncate(status, 200))
			}
			return unknown("csrutil status: %s", truncate(status, 120))
		}},
	{control{id: "MACOS-03", category: categoryMacProtection, severity: "high", title: "Gatekeeper checks apps before they open",
		rationale:   "Gatekeeper opens only apps from the App Store or identified, notarized developers, which blocks most downloaded malware.",
		remediation: "Run sudo spctl --global-enable, or allow apps from the App Store and identified developers in System Settings → Privacy & Security."},
		func(m *macMachine) (string, string) {
			status := strings.TrimSpace(m.facts["gatekeeper"])
			switch status {
			case "assessments enabled":
				return pass("%s", status)
			case "assessments disabled":
				return fail("%s", status)
			}
			return unknown("spctl --status: %s", truncate(status, 120))
		}},
	{control{id: "MACOS-04", category: categoryMacProtection, severity: "medium", title: "XProtect's malware definitions are recent",
		rationale:   "XProtect is macOS's built-in malware scanner; Apple updates its definitions often, without a macOS update.",
		remediation: "Install security responses and system data files automatically (see MACOS-14), or run softwareupdate --background-critical."},
		func(m *macMachine) (string, string) {
			fields := strings.Fields(m.facts["xprotect"])
			if len(fields) < 2 {
				return unknown("XProtect's version couldn't be read")
			}
			modified, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
			if err != nil {
				return unknown("XProtect's update time couldn't be read")
			}
			age := m.now.Sub(time.Unix(modified, 0))
			if age > 45*24*time.Hour {
				return fail("XProtect %s, last updated %d days ago", fields[0], int(age.Hours()/24))
			}
			return pass("XProtect %s, updated %d days ago", fields[0], int(age.Hours()/24))
		}},
	{control{id: "MACOS-05", category: categoryServices, severity: "medium", title: "The firewall is on",
		rationale:   "The application firewall refuses incoming connections to apps that weren't allowed, so a service started by mistake isn't reachable.",
		remediation: "Turn on the firewall in System Settings → Network → Firewall."},
		func(m *macMachine) (string, string) {
			status := strings.TrimSpace(m.facts["firewall"])
			switch {
			case strings.Contains(status, "State = 1"), strings.Contains(status, "State = 2"):
				return pass("%s", status)
			case strings.Contains(status, "State = 0"), strings.Contains(status, "is disabled"):
				return fail("%s", status)
			}
			return unknown("socketfilterfw: %s", truncate(status, 120))
		}},
	{control{id: "MACOS-06", category: categoryServices, severity: "low", title: "The firewall's stealth mode is on",
		rationale:   "In stealth mode the Mac doesn't answer pings or probes of closed ports, so scans of the network don't find it as easily.",
		remediation: "Turn on stealth mode in System Settings → Network → Firewall → Options."},
		func(m *macMachine) (string, string) {
			status := strings.TrimSpace(m.facts["stealth"])
			switch {
			case strings.HasSuffix(status, "is on"), strings.Contains(status, "enabled"):
				return pass("%s", status)
			case strings.HasSuffix(status, "is off"), strings.Contains(status, "disabled"):
				return fail("%s", status)
			}
			return unknown("socketfilterfw: %s", truncate(status, 120))
		}},
	{control{id: "MACOS-07", category: categoryServices, severity: "medium", title: "Remote Login (SSH) is off",
		rationale:   "With Remote Login on, anyone who can reach the Mac can try passwords over SSH. Most Macs don't need it.",
		remediation: "Turn off Remote Login in System Settings → General → Sharing, or allow it only for the accounts that need it."},
		func(m *macMachine) (string, string) {
			if status := strings.TrimSpace(m.facts["remote-login"]); strings.HasPrefix(status, "Remote Login:") {
				if strings.HasSuffix(status, "Off") {
					return pass("%s", status)
				}
				return fail("%s", status)
			}
			switch m.launchd("com.openssh.sshd") {
			case "enabled":
				return fail("com.openssh.sshd is enabled in launchd")
			case "disabled", "":
				return pass("com.openssh.sshd isn't enabled in launchd")
			}
			return unknown("Remote Login's state couldn't be read")
		}},
	{control{id: "MACOS-08", category: categoryServices, severity: "medium", title: "Screen Sharing and Remote Management are off",
		rationale:   "Screen Sharing and Remote Management let others see and control the Mac over the network. If your MDM or IT team uses them, accept this control in the audit.",
		remediation: "Turn off Screen Sharing and Remote Management in System Settings → General → Sharing."},
		func(m *macMachine) (string, string) {
			if m.launchd("com.apple.screensharing") == "enabled" {
				return fail("com.apple.screensharing is enabled in launchd")
			}
			return pass("com.apple.screensharing isn't enabled")
		}},
	{control{id: "MACOS-09", category: categoryServices, severity: "low", title: "File Sharing is off",
		rationale:   "File Sharing serves folders over SMB to the network, an easy place to expose files by mistake.",
		remediation: "Turn off File Sharing in System Settings → General → Sharing, unless this Mac is meant to share files."},
		func(m *macMachine) (string, string) {
			if m.launchd("com.apple.smbd") == "enabled" {
				return fail("com.apple.smbd is enabled in launchd")
			}
			return pass("com.apple.smbd isn't enabled")
		}},
	{control{id: "MACOS-10", category: categoryAccounts, severity: "medium", title: "The guest account is off",
		rationale:   "The guest account lets anyone at the Mac sign in without a password.",
		remediation: "Turn off the guest user in System Settings → Users & Groups."},
		func(m *macMachine) (string, string) {
			if disabled, source := m.setting("com.apple.MCX", "DisableGuestAccount"); disabled == "true" {
				return pass("guest account disabled (%s)", source)
			}
			switch value, source := m.setting("com.apple.loginwindow", "GuestEnabled"); value {
			case "true", "1":
				return fail("GuestEnabled is on (%s)", source)
			case "":
				return pass("GuestEnabled isn't set (the macOS default: off)")
			default:
				return pass("GuestEnabled is off (%s)", source)
			}
		}},
	{control{id: "MACOS-11", category: categoryAccounts, severity: "high", title: "Automatic login is off",
		rationale:   "With automatic login, anyone who turns the Mac on is signed in, without a password.",
		remediation: "Turn off automatic login in System Settings → Users & Groups."},
		func(m *macMachine) (string, string) {
			if user, source := m.setting("com.apple.loginwindow", "autoLoginUser"); user != "" {
				return fail("automatic login as %s (%s)", user, source)
			}
			return pass("no automatic login")
		}},
	{control{id: "MACOS-12", category: categoryUpdates, severity: "medium", title: "The Mac checks for updates automatically",
		rationale:   "A Mac that doesn't check for updates doesn't learn that security fixes are waiting.",
		remediation: "Turn on Automatic Updates in System Settings → General → Software Update."},
		func(m *macMachine) (string, string) {
			return m.enabledByDefault("com.apple.SoftwareUpdate", "AutomaticCheckEnabled", "checking for updates")
		}},
	{control{id: "MACOS-13", category: categoryUpdates, severity: "low", title: "macOS updates download automatically",
		rationale:   "Downloaded updates install in minutes, so fixes aren't put off.",
		remediation: "Turn on \"Download new updates when available\" in System Settings → General → Software Update → Automatic Updates."},
		func(m *macMachine) (string, string) {
			return m.enabledByDefault("com.apple.SoftwareUpdate", "AutomaticDownload", "downloading updates")
		}},
	{control{id: "MACOS-14", category: categoryUpdates, severity: "high", title: "Security responses and system files install automatically",
		rationale:   "Apple ships urgent security fixes (Background Security Improvements) and XProtect's definitions this way, often for flaws being exploited.",
		remediation: "Turn on \"Install Security Responses and system files\" in System Settings → General → Software Update → Automatic Updates."},
		func(m *macMachine) (string, string) {
			if status, evidence := m.enabledByDefault("com.apple.SoftwareUpdate", "CriticalUpdateInstall", "security responses"); status != ControlPass {
				return status, evidence
			}
			return m.enabledByDefault("com.apple.SoftwareUpdate", "ConfigDataInstall", "security responses and system data files")
		}},
	{control{id: "MACOS-15", category: categoryUpdates, severity: "low", title: "macOS updates install automatically",
		rationale:   "Installing updates automatically, overnight, is how most Macs stay current.",
		remediation: "Turn on \"Install macOS updates\" in System Settings → General → Software Update → Automatic Updates, or have your MDM enforce updates."},
		func(m *macMachine) (string, string) {
			value, source := m.setting("com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates")
			if value == "true" || value == "1" {
				return pass("installing macOS updates: on (%s)", source)
			}
			if value == "" {
				return fail("installing macOS updates: off (the macOS default)")
			}
			return fail("installing macOS updates: off (%s)", source)
		}},
	{control{id: "MACOS-16", category: categoryUpdates, severity: "low", title: "App Store apps update automatically",
		rationale:   "Apps from the App Store get security fixes too; updating them automatically keeps them current.",
		remediation: "Turn on \"Install application updates from the App Store\" in System Settings → General → Software Update → Automatic Updates."},
		func(m *macMachine) (string, string) {
			for _, setting := range [][2]string{{"com.apple.SoftwareUpdate", "AutomaticallyInstallAppUpdates"}, {"com.apple.commerce", "AutoUpdate"}} {
				if value, source := m.setting(setting[0], setting[1]); value != "" {
					if value == "true" || value == "1" {
						return pass("App Store updates: on (%s)", source)
					}
					return fail("App Store updates: off (%s)", source)
				}
			}
			return unknown("the App Store update setting isn't saved where it can be read")
		}},
	{control{id: "MACOS-17", category: categoryUpdates, severity: "medium", title: "No found updates are waiting to be installed",
		rationale:   "An update the Mac has already found but not installed leaves its fixes unused.",
		remediation: "Install the updates in System Settings → General → Software Update."},
		func(m *macMachine) (string, string) {
			output := m.facts["updates"]
			if strings.Contains(output, "No new software available") {
				return pass("no updates waiting")
			}
			var titles []string
			for _, line := range strings.Split(output, "\n") {
				if label, found := strings.CutPrefix(strings.TrimSpace(line), "* Label:"); found {
					titles = append(titles, strings.TrimSpace(label))
				}
			}
			if len(titles) > 0 {
				return fail("waiting: %s", truncate(strings.Join(titles, "; "), 300))
			}
			return unknown("softwareupdate's list couldn't be read")
		}},
	{control{id: "MACOS-18", category: categoryTime, severity: "low", title: "The clock is set automatically",
		rationale:   "Logs, certificates and two-step codes rely on the right time.",
		remediation: "Turn on \"Set time and date automatically\" in System Settings → General → Date & Time."},
		func(m *macMachine) (string, string) {
			status := strings.TrimSpace(m.facts["network-time"])
			switch status {
			case "Network Time: On":
				return pass("%s", status)
			case "Network Time: Off":
				return fail("%s", status)
			}
			if !m.root {
				return unknown(needsRoot)
			}
			return unknown("systemsetup: %s", truncate(status, 120))
		}},
}

// MacOSChecks are the checks a Mac runs; the others don't apply to macOS.
var MacOSChecks = []string{Packages, Hardening}

// macOSSkipped says why a check doesn't run on a Mac.
func macOSSkipped(id string) Result {
	reasons := map[string]string{
		Integrity:  "macOS protects its own system files with System Integrity Protection and a signed system volume; the hardening audit checks that it is on",
		Containers: "containers on a Mac run inside a Linux virtual machine (Docker Desktop, Podman, Colima); scan that machine or its images instead",
		Config:     "on a Mac, the hardening audit checks these settings",
	}
	reason, known := reasons[id]
	if !known {
		reason = "this check doesn't run on macOS yet"
	}
	return Result{Status: StatusSkipped, Summary: "Not on macOS: " + reason, Findings: []Finding{}, Notes: []string{}}
}

// MacOSControls is how many controls the macOS baseline has.
func MacOSControls() int { return len(macBaseline) }

func runMacHardening(executor *Executor, target platform.Platform) Result {
	var result Result
	output, _, privileged, err := executor.RunPrivileged(script(macFacts()), 8<<20, factsTimeout)
	if err != nil {
		return failed(fmt.Errorf("read the Mac's settings: %w", err))
	}
	m := newMacMachine(sections(output), privileged, time.Now())
	if !privileged {
		result.note("Settings that need root, such as Remote Login, network time and services every account listens on, were read only partly. The agent runs as root; run a local audit with sudo for a complete result.")
	}
	result.Inventory = m.inventory(target)
	for _, item := range macBaseline {
		outcome := ControlResult{ID: item.id, Category: item.category, Title: item.title, Severity: item.severity,
			Rationale: item.rationale, Remediation: item.remediation}
		outcome.Status, outcome.Evidence = item.check(m)
		result.Controls = append(result.Controls, outcome)
		if outcome.Status == ControlFail {
			result.add(Finding{Rule: "hardening." + item.id, Severity: strings.ToUpper(item.severity), Title: item.title,
				Detail: item.rationale + " " + item.remediation, Evidence: outcome.Evidence})
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
	return result.finish(!privileged)
}

func (m *macMachine) inventory(target platform.Platform) *Inventory {
	osLines := lines([]byte(m.facts["os"]))
	inventory := &Inventory{OS: "macOS " + target.VersionID, Hostname: strings.TrimSpace(m.facts["hostname"]),
		Virtualization: map[string]string{"0": "none", "1": "virtual machine"}[strings.TrimSpace(m.facts["vmm"])], Timezone: strings.TrimPrefix(strings.TrimSpace(m.facts["timezone"]), "/var/db/timezone/zoneinfo/")}
	if len(osLines) > 1 {
		inventory.OS += " (" + strings.TrimSpace(osLines[1]) + ")"
	}
	if fields := strings.Fields(m.facts["uname"]); len(fields) >= 3 {
		inventory.Kernel, inventory.Architecture = fields[0]+" "+fields[1], fields[2]
	}
	if match := regexp.MustCompile(`sec = (\d+)`).FindStringSubmatch(m.facts["boottime"]); match != nil {
		if booted, err := strconv.ParseInt(match[1], 10, 64); err == nil {
			inventory.UptimeSeconds = int64(m.now.Sub(time.Unix(booted, 0)).Seconds())
		}
	}
	inventory.CPUs, _ = strconv.Atoi(strings.TrimSpace(m.facts["cpus"]))
	inventory.MemoryBytes, _ = strconv.ParseInt(strings.TrimSpace(m.facts["memory"]), 10, 64)
	for index, line := range lines([]byte(m.facts["disks"])) {
		fields := strings.Fields(line)
		if index == 0 || len(fields) < 6 {
			continue
		}
		size, _ := strconv.ParseInt(fields[1], 10, 64)
		used, _ := strconv.ParseInt(fields[2], 10, 64)
		percent, _ := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		inventory.Disks = append(inventory.Disks, Disk{Mount: fields[len(fields)-1], SizeBytes: size * 1024, UsedBytes: used * 1024, UsedPercent: percent})
	}
	device := ""
	for _, line := range lines([]byte(m.facts["addresses"])) {
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			device = strings.TrimSuffix(strings.Fields(line + " x")[0], ":")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "inet" || fields[0] == "inet6") && device != "lo0" && !strings.HasPrefix(fields[1], "fe80:") {
			inventory.Addresses = append(inventory.Addresses, device+" "+strings.Split(fields[1], "%")[0])
		}
	}
	if members, found := strings.CutPrefix(strings.TrimSpace(m.facts["admins"]), "GroupMembership:"); found {
		inventory.Administrators = strings.Fields(members)
	}
	for _, line := range lines([]byte(m.facts["users"])) {
		fields := strings.Fields(line)
		if len(fields) == 2 && !strings.HasPrefix(fields[0], "_") {
			if uid, err := strconv.Atoi(fields[1]); err == nil && uid >= 501 {
				inventory.LoginUsers = append(inventory.LoginUsers, fields[0])
			}
		}
	}
	seen := map[string]bool{}
	for _, line := range lines([]byte(m.facts["listening"])) {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] == "COMMAND" {
			continue
		}
		name := fields[len(fields)-2]
		if fields[len(fields)-1] != "(LISTEN)" {
			continue
		}
		at := strings.LastIndex(name, ":")
		port, err := strconv.Atoi(name[at+1:])
		if at < 0 || err != nil || seen[name] {
			continue
		}
		seen[name] = true
		address := name[:at]
		inventory.Listening = append(inventory.Listening, Listening{Protocol: "tcp", Address: address, Port: port,
			Exposed: address == "*" || address == "0.0.0.0" || address == "[::]"})
	}
	return inventory
}
