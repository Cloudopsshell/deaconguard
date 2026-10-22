package checks

import (
	"strings"
	"testing"
	"time"

	"deaconguard/internal/platform"
)

// macFactsOf is a Mac's command output, as a script section map: a managed
// Mac with FileVault, SIP, Gatekeeper and the firewall on, and Screen
// Sharing enabled for its MDM.
func macFactsOf(overrides map[string]string) map[string]string {
	facts := map[string]string{
		"os":               "27.0.1\n26A434",
		"uname":            "Darwin 27.0.0 arm64",
		"now":              "1792540000",
		"filevault":        "FileVault is On.",
		"sip":              "System Integrity Protection status: enabled.",
		"gatekeeper":       "assessments enabled",
		"firewall":         "Firewall is enabled. (State = 1)",
		"stealth":          "Firewall stealth mode is on",
		"launchd-disabled": "\tdisabled services = {\n\t\t\"com.apple.screensharing\" => enabled\n\t\t\"com.openssh.sshd\" => disabled\n\t}",
		"remote-login":     "You need administrator access to run this tool... exiting!",
		"network-time":     "You need administrator access to run this tool... exiting!",
		"xprotect":         "5367\n1791562788",
		"updates":          "Software Update Tool\n\nNo new software available.",
		"managed:com.apple.SoftwareUpdate": `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>AutomaticCheckEnabled</key><true/>
	<key>ConfigDataInstall</key><true/>
	<key>CriticalUpdateInstall</key><false/>
	<key>Nested</key><dict><key>AutomaticCheckEnabled</key><false/></dict>
</dict></plist>`,
		"pref:com.apple.loginwindow": `<plist version="1.0"><dict><key>GuestEnabled</key><false/><key>lastUserName</key><string>ann</string></dict></plist>`,
		"listening":                  "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nrapportd  612 ann    9u  IPv4 0x1      0t0  TCP *:49152 (LISTEN)\nnode     900 ann   20u  IPv4 0x2      0t0  TCP 127.0.0.1:3000 (LISTEN)",
	}
	for name, value := range overrides {
		facts[name] = value
	}
	return facts
}

func macControls(t *testing.T, facts map[string]string, root bool) map[string]ControlResult {
	t.Helper()
	m := newMacMachine(facts, root, time.Time{})
	results := map[string]ControlResult{}
	for _, item := range macBaseline {
		status, evidence := item.check(m)
		results[item.id] = ControlResult{ID: item.id, Status: status, Evidence: evidence}
	}
	return results
}

func TestMacControls(t *testing.T) {
	got := macControls(t, macFactsOf(nil), false)
	want := map[string]string{
		"MACOS-01": ControlPass, "MACOS-02": ControlPass, "MACOS-03": ControlPass, "MACOS-04": ControlPass, "MACOS-05": ControlPass,
		"MACOS-06": ControlPass, "MACOS-07": ControlPass, "MACOS-08": ControlFail, "MACOS-09": ControlPass, "MACOS-10": ControlPass,
		"MACOS-11": ControlPass, "MACOS-12": ControlPass,
		// The profile turns security responses off, which a local setting can't undo.
		"MACOS-14": ControlFail, "MACOS-15": ControlFail, "MACOS-17": ControlPass, "MACOS-18": ControlUnknown,
	}
	for id, status := range want {
		if got[id].Status != status {
			t.Errorf("%s: %s (%s), want %s", id, got[id].Status, got[id].Evidence, status)
		}
	}
	if !strings.Contains(got["MACOS-12"].Evidence, "configuration profile") {
		t.Errorf("MACOS-12 evidence: %s", got["MACOS-12"].Evidence)
	}

	bad := macControls(t, macFactsOf(map[string]string{
		"filevault": "FileVault is Off.", "sip": "System Integrity Protection status: disabled.", "gatekeeper": "assessments disabled",
		"firewall": "Firewall is disabled. (State = 0)", "remote-login": "Remote Login: On", "network-time": "Network Time: Off",
		"xprotect": "5100\n1780000000", "updates": "Software Update found the following new or updated software:\n* Label: Safari26.7-26.7\n\tTitle: Safari, Version: 26.7, Size: 200000KiB, Recommended: YES,",
		"pref:com.apple.loginwindow": `<plist><dict><key>GuestEnabled</key><true/><key>autoLoginUser</key><string>ann</string></dict></plist>`,
	}), true)
	for _, id := range []string{"MACOS-01", "MACOS-02", "MACOS-03", "MACOS-04", "MACOS-05", "MACOS-07", "MACOS-10", "MACOS-11", "MACOS-17", "MACOS-18"} {
		if bad[id].Status != ControlFail {
			t.Errorf("%s on a weak Mac: %s (%s)", id, bad[id].Status, bad[id].Evidence)
		}
	}
	if !strings.Contains(bad["MACOS-17"].Evidence, "Safari26.7") {
		t.Errorf("MACOS-17 evidence: %s", bad["MACOS-17"].Evidence)
	}
}

func TestMacInventory(t *testing.T) {
	m := newMacMachine(macFactsOf(map[string]string{"vmm": "1", "boottime": "{ sec = 1792530000, usec = 5 } Tue", "cpus": "8", "memory": "25769803776"}), false, time.Time{})
	inventory := m.inventory(platform.Platform{Family: platform.MacOS, VersionID: "27.0.1"})
	if inventory.OS != "macOS 27.0.1 (26A434)" || inventory.Architecture != "arm64" || inventory.UptimeSeconds != 10000 ||
		inventory.Virtualization != "virtual machine" || inventory.CPUs != 8 || len(inventory.Listening) != 2 {
		t.Fatalf("inventory: %+v", inventory)
	}
	if !inventory.Listening[0].Exposed || inventory.Listening[1].Exposed {
		t.Errorf("listening: %+v", inventory.Listening)
	}
}

func TestMacSkipsLinuxChecks(t *testing.T) {
	mac := platform.Platform{Family: platform.MacOS, VersionID: "27.0.1"}
	for _, id := range []string{Integrity, Containers, Config, Antivirus} {
		if result := Run(id, nil, mac, time.Now(), Inputs{}); result.Status != StatusSkipped || !strings.HasPrefix(result.Summary, "Not on macOS") {
			t.Errorf("%s on a Mac: %+v", id, result)
		}
	}
}
