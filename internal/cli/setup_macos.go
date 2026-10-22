package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// On a Mac the agent runs as a launchd daemon. install.sh puts the binary in
// /usr/local/bin and runs `deaconguard setup agent`, which writes this
// daemon's property list and (re)starts it.
const (
	macAgentLabel  = "io.deaconguard.agent"
	macAgentPlist  = "/Library/LaunchDaemons/" + macAgentLabel + ".plist"
	macAgentBinary = "/usr/local/bin/deaconguard"
	macAgentLog    = "/var/log/deaconguard-agent.log"
)

// macAgentDaemon is the agent's launchd property list: it runs as root at
// boot, and launchd restarts it when it fails. An agent whose host was
// removed exits successfully and stays stopped. PATH has the system tools
// the checks run, such as systemsetup in /usr/sbin.
func macAgentDaemon() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + macAgentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + macAgentBinary + `</string>
		<string>agent</string>
		<string>run</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>` + macAgentLog + `</string>
	<key>StandardErrorPath</key>
	<string>` + macAgentLog + `</string>
</dict>
</plist>
`
}

func launchctl(arguments ...string) (string, error) {
	combined, err := exec.Command("/bin/launchctl", arguments...).CombinedOutput()
	if err != nil {
		return string(combined), fmt.Errorf("launchctl %s: %v: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(combined)))
	}
	return string(combined), nil
}

// macAgentRunning reports whether launchd runs the agent.
func macAgentRunning() bool {
	status, err := launchctl("print", "system/"+macAgentLabel)
	return err == nil && strings.Contains(status, "state = running")
}

// setupMacAgent enrolls a Mac and starts its agent daemon. It always
// restarts the daemon: on a Mac, install.sh replaces the binary itself, and
// no package manager restarts the service for it.
func setupMacAgent(options agentSetup, output, diagnostics io.Writer) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup configures a system service; run it with sudo")
	}
	if _, err := os.Stat(macAgentBinary); err != nil {
		return fmt.Errorf("%s is missing; install DeaconGuard with the install script first", macAgentBinary)
	}
	if _, err := enrollForSetup(options, output, diagnostics); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(macAgentPlist), 0o755); err != nil {
		return err
	}
	temporary := macAgentPlist + ".tmp"
	if err := os.WriteFile(temporary, []byte(macAgentDaemon()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, macAgentPlist); err != nil {
		return err
	}
	// bootout fails when the daemon isn't loaded, which is fine.
	_, _ = launchctl("bootout", "system/"+macAgentLabel)
	if _, err := launchctl("bootstrap", "system", macAgentPlist); err != nil {
		return err
	}
	// The agent exits soon if the server rejects it; give it a moment.
	time.Sleep(3 * time.Second)
	if !macAgentRunning() {
		return fmt.Errorf("the agent stopped after starting; see what happened: tail -n 30 %s", macAgentLog)
	}
	fmt.Fprintf(output, "The DeaconGuard agent is running as the launchd daemon %s. This Mac appears on the server's Agents page.\n", macAgentLabel)
	return nil
}
