package checks

import (
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/platform"
)

const configTimeout = time.Minute

const (
	sshdConfigCommand = `for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do [ -r "$f" ] && printf '==> %s <==\n' "$f" && cat "$f"; done 2>/dev/null; true`
	listeningCommand  = "ss -H -tuln 2>/dev/null || netstat -tuln 2>/dev/null"
	rebootDebian      = "if [ -f /var/run/reboot-required ]; then echo REBOOT_REQUIRED; cat /var/run/reboot-required.pkgs 2>/dev/null; fi; true"
	rebootRPM         = "if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1; echo \"EXIT $?\"; fi; true"
	autoUpdateDebian  = "cat /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -i 'Unattended-Upgrade\"' ; true"
	autoUpdateRPM     = "systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null; true"
	firewallCommand   = "(ufw status 2>/dev/null; firewall-cmd --state 2>/dev/null; nft list ruleset 2>/dev/null | head -n 2000; iptables -S 2>/dev/null | head -n 2000) ; true"
)

// Services that should rarely be reachable from other machines.
var exposedServices = map[int]struct {
	name     string
	severity string
}{
	21: {"FTP", "HIGH"}, 23: {"Telnet", "HIGH"}, 512: {"rexec", "HIGH"}, 513: {"rlogin", "HIGH"}, 514: {"rsh", "HIGH"},
	2375: {"Docker API without TLS", "CRITICAL"}, 3306: {"MySQL", "MEDIUM"}, 5432: {"PostgreSQL", "MEDIUM"},
	5900: {"VNC", "MEDIUM"}, 5984: {"CouchDB", "MEDIUM"}, 6379: {"Redis", "MEDIUM"}, 9200: {"Elasticsearch", "MEDIUM"},
	11211: {"Memcached", "MEDIUM"}, 27017: {"MongoDB", "MEDIUM"},
}

func runConfig(executor *Executor, target platform.Platform) Result {
	var result Result
	partial := false
	debian := target.Family == platform.Ubuntu || target.Family == platform.Debian

	if output, _, err := executor.Run(sshdConfigCommand, 1<<20, configTimeout); err == nil && len(output) > 0 {
		checkSSHD(&result, effectiveSSHD(output))
	} else {
		result.note("The SSH server configuration could not be read.")
		partial = true
	}

	if output, _, err := executor.Run(listeningCommand, 1<<20, configTimeout); err == nil && len(output) > 0 {
		checkListening(&result, output)
	} else {
		result.note("Listening services could not be listed (neither ss nor netstat is available).")
		partial = true
	}

	if debian {
		if output, _, err := executor.Run(rebootDebian, 64<<10, configTimeout); err == nil {
			checkRebootDebian(&result, output)
		}
		if output, _, err := executor.Run(autoUpdateDebian, 64<<10, configTimeout); err == nil {
			checkAutoUpdatesDebian(&result, output)
		}
	} else {
		if output, _, err := executor.Run(rebootRPM, 64<<10, configTimeout); err == nil {
			checkRebootRPM(&result, output)
		}
		if output, _, err := executor.Run(autoUpdateRPM, 64<<10, configTimeout); err == nil {
			checkAutoUpdatesRPM(&result, output)
		}
	}

	privileged := executor.Privileged()
	if privileged {
		if output, _, _, err := executor.RunPrivileged(firewallCommand, 4<<20, configTimeout); err == nil {
			checkFirewall(&result, output)
		} else {
			result.note("The host firewall could not be read: %s", truncate(err.Error(), 160))
			partial = true
		}
	} else {
		result.note("The host firewall was not checked because reading it requires sudo.")
		partial = true
	}
	result.Privileged = privileged
	return result.finish(partial)
}

// effectiveSSHD returns the sshd settings that apply outside Match blocks.
// sshd uses the first value it reads for most keywords, and the stock
// "Include /etc/ssh/sshd_config.d/*.conf" is expanded where it appears.
func effectiveSSHD(output []byte) map[string]string {
	files := make(map[string][]string)
	var order []string
	current := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "==> ") && strings.HasSuffix(line, " <==") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "==> "), " <==")
			order = append(order, current)
			continue
		}
		if current != "" {
			files[current] = append(files[current], line)
		}
	}
	settings := make(map[string]string)
	var apply func(name string, depth int)
	apply = func(name string, depth int) {
		if depth > 4 {
			return
		}
		for _, line := range files[name] {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			keyword := strings.ToLower(fields[0])
			if keyword == "match" {
				return
			}
			if keyword == "include" {
				for _, pattern := range fields[1:] {
					if !strings.HasPrefix(pattern, "/") {
						pattern = "/etc/ssh/" + pattern
					}
					var included []string
					for _, candidate := range order {
						if matched, _ := path.Match(pattern, candidate); matched {
							included = append(included, candidate)
						}
					}
					sort.Strings(included)
					for _, file := range included {
						apply(file, depth+1)
					}
				}
				continue
			}
			if _, set := settings[keyword]; !set && len(fields) > 1 {
				settings[keyword] = strings.ToLower(fields[1])
			}
		}
	}
	apply("/etc/ssh/sshd_config", 0)
	return settings
}

func checkSSHD(result *Result, settings map[string]string) {
	if settings["permitrootlogin"] == "yes" {
		result.add(Finding{
			Rule: "config.ssh-root-login", Severity: "HIGH", Title: "SSH allows root to log in with a password",
			Detail:   "PermitRootLogin yes lets attackers guess the root password directly. Use prohibit-password or no.",
			Evidence: "PermitRootLogin yes",
		})
	}
	if settings["permitemptypasswords"] == "yes" {
		result.add(Finding{
			Rule: "config.ssh-empty-passwords", Severity: "CRITICAL", Title: "SSH accepts accounts with empty passwords",
			Detail: "PermitEmptyPasswords yes lets anyone log in to an account that has no password.", Evidence: "PermitEmptyPasswords yes",
		})
	}
	if value, set := settings["passwordauthentication"]; !set || value == "yes" {
		evidence := "PasswordAuthentication yes"
		if !set {
			evidence = "PasswordAuthentication not set (OpenSSH defaults to yes)"
		}
		result.add(Finding{
			Rule: "config.ssh-password-auth", Severity: "MEDIUM", Title: "SSH password login is enabled",
			Detail:   "Password logins can be brute-forced. Prefer key-only access with PasswordAuthentication no.",
			Evidence: evidence,
		})
	}
	if settings["x11forwarding"] == "yes" {
		result.add(Finding{
			Rule: "config.ssh-x11", Severity: "LOW", Title: "SSH X11 forwarding is enabled",
			Detail: "X11 forwarding is rarely needed on servers and widens what a compromised client can reach.", Evidence: "X11Forwarding yes",
		})
	}
}

// checkListening reports risky services bound to every interface. ss and
// netstat both print the local address in the column after the queue sizes.
func checkListening(result *Result, output []byte) {
	seen := make(map[string]bool)
	for _, line := range lines(output) {
		fields := strings.Fields(line)
		local := ""
		for index, field := range fields {
			if index > 0 && strings.Contains(field, ":") && (fields[0] == "tcp" || fields[0] == "udp" ||
				strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp")) {
				local = field
				break
			}
		}
		if local == "" {
			continue
		}
		separator := strings.LastIndex(local, ":")
		host, portText := strings.Trim(local[:separator], "[]"), local[separator+1:]
		port, err := strconv.Atoi(portText)
		if err != nil {
			continue
		}
		host, _, _ = strings.Cut(host, "%")
		if !(host == "*" || host == "0.0.0.0" || host == "::" || host == "") {
			if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
				continue
			}
		}
		service, risky := exposedServices[port]
		key := fmt.Sprintf("%s/%d", fields[0][:3], port)
		if !risky || seen[key] {
			continue
		}
		seen[key] = true
		result.add(Finding{
			Rule: "config.exposed-service", Severity: service.severity,
			Title:    fmt.Sprintf("%s is listening on all network interfaces", service.name),
			Detail:   "The service accepts connections from other machines unless a firewall or cloud security group blocks the port. Bind it to 127.0.0.1 or restrict access.",
			Evidence: fmt.Sprintf("%s port %d on %s", strings.ToUpper(fields[0][:3]), port, local),
		})
	}
}

func checkRebootDebian(result *Result, output []byte) {
	entries := lines(output)
	if len(entries) == 0 || entries[0] != "REBOOT_REQUIRED" {
		return
	}
	evidence := "/var/run/reboot-required exists"
	if len(entries) > 1 {
		evidence += "; packages: " + truncate(strings.Join(entries[1:], ", "), 300)
	}
	result.add(Finding{
		Rule: "config.reboot-required", Severity: "MEDIUM", Title: "Reboot required to finish applying updates",
		Detail:   "Updated packages, often the kernel or core libraries, only take effect after a reboot. Until then the old, vulnerable code keeps running.",
		Evidence: evidence,
	})
}

func checkRebootRPM(result *Result, output []byte) {
	if strings.TrimSpace(string(output)) == "EXIT 1" {
		result.add(Finding{
			Rule: "config.reboot-required", Severity: "MEDIUM", Title: "Reboot required to finish applying updates",
			Detail:   "needs-restarting reports that core packages were updated since boot. The old, vulnerable code keeps running until a reboot.",
			Evidence: "needs-restarting -r exited with status 1",
		})
	}
}

func checkAutoUpdatesDebian(result *Result, output []byte) {
	for _, line := range lines(output) {
		if strings.Contains(line, "APT::Periodic::Unattended-Upgrade") && strings.Contains(line, `"1"`) {
			return
		}
	}
	result.add(Finding{
		Rule: "config.auto-updates-off", Severity: "LOW", Title: "Automatic security updates are not enabled",
		Detail:   "unattended-upgrades installs security fixes daily. Without it, fixes wait for someone to apply them.",
		Evidence: `APT::Periodic::Unattended-Upgrade "1" not found in /etc/apt/apt.conf.d`,
	})
}

func checkAutoUpdatesRPM(result *Result, output []byte) {
	for _, line := range lines(output) {
		if strings.TrimSpace(line) == "enabled" {
			return
		}
	}
	result.add(Finding{
		Rule: "config.auto-updates-off", Severity: "LOW", Title: "Automatic security updates are not enabled",
		Detail:   "dnf-automatic installs updates on a schedule. Without it, fixes wait for someone to apply them.",
		Evidence: "dnf-automatic.timer and dnf-automatic-install.timer are not enabled",
	})
}

func checkFirewall(result *Result, output []byte) {
	text := strings.ToLower(string(output))
	active := strings.Contains(text, "status: active") || strings.Contains(text, "\nrunning") || strings.HasPrefix(text, "running") ||
		strings.Contains(text, "policy drop") || strings.Contains(text, " drop") || strings.Contains(text, " reject") ||
		strings.Contains(text, "-p input drop") || strings.Contains(text, "-j drop") || strings.Contains(text, "-j reject")
	if active {
		return
	}
	result.add(Finding{
		Rule: "config.no-firewall", Severity: "LOW", Title: "No host firewall rules are active",
		Detail:   "ufw, firewalld, nftables, and iptables have no blocking rules. A cloud security group may still restrict traffic; a host firewall adds a second layer.",
		Evidence: "no active ufw/firewalld status and no drop or reject rules",
	})
}
