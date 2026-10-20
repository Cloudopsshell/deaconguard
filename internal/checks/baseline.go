package checks

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

// control is one rule of the DeaconGuard Linux baseline. check returns a
// status and the evidence it found, never secrets.
type control struct {
	id, category, title, severity string
	rationale, remediation        string
	check                         func(*machine) (string, string)
}

// Categories, in the order reports show them.
const (
	categoryAccounts   = "Accounts and passwords"
	categorySSH        = "SSH"
	categoryNetwork    = "Network"
	categoryKernel     = "Kernel"
	categoryServices   = "Services and firewall"
	categoryLogging    = "Logging and auditing"
	categoryFiles      = "Files and permissions"
	categoryUpdates    = "Updates"
	categoryTime       = "Time"
	categoryProtection = "Mandatory access control"
)

// Categories lists the baseline's categories in display order.
func Categories() []string {
	return []string{categoryMacProtection, categoryAccounts, categorySSH, categoryNetwork, categoryKernel, categoryServices,
		categoryLogging, categoryFiles, categoryUpdates, categoryTime, categoryProtection}
}

const needsRoot = "needs root to check"

func pass(format string, arguments ...any) (string, string) {
	return ControlPass, fmt.Sprintf(format, arguments...)
}

func fail(format string, arguments ...any) (string, string) {
	return ControlFail, fmt.Sprintf(format, arguments...)
}

func notApplicable(format string, arguments ...any) (string, string) {
	return ControlNA, fmt.Sprintf(format, arguments...)
}

func unknown(format string, arguments ...any) (string, string) {
	return ControlUnknown, fmt.Sprintf(format, arguments...)
}

// sysctlIs checks that a kernel setting has one of the allowed values.
func sysctlIs(key string, allowed ...string) func(*machine) (string, string) {
	return func(m *machine) (string, string) {
		value, set := m.sysctl[key]
		if !set {
			if !m.collected("sysctl") {
				return unknown("the kernel settings could not be read")
			}
			return notApplicable("%s does not exist on this kernel", key)
		}
		for _, want := range allowed {
			if value == want {
				return pass("%s = %s", key, value)
			}
		}
		return fail("%s = %s (expected %s)", key, value, strings.Join(allowed, " or "))
	}
}

// forwardingHost reports whether the machine runs containers or virtual
// machines, which need IP forwarding.
func (m *machine) forwardingHost() string {
	if found := m.installed("docker-ce", "docker.io", "docker", "moby-engine", "containerd", "containerd.io", "podman",
		"kubelet", "k3s", "libvirt-daemon", "libvirt-daemon-system", "lxd"); len(found) > 0 {
		return found[0]
	}
	if m.anyActive("docker", "containerd", "kubelet", "k3s", "k3s-agent", "libvirtd") != "" {
		return "a container or VM service"
	}
	return ""
}

// sshdIs checks an SSH server setting against allowed values.
func sshdIs(key string, allowed ...string) func(*machine) (string, string) {
	return func(m *machine) (string, string) {
		if m.sshd == nil {
			return m.noSSH()
		}
		value := m.sshd[key]
		for _, want := range allowed {
			if value == want {
				return pass("%s %s (from %s)", key, value, m.sshdSource)
			}
		}
		return fail("%s %s (from %s)", key, value, m.sshdSource)
	}
}

// sshdAtMost checks that a numeric SSH setting is at most limit; zero
// counts as unlimited unless zeroFails is false.
func sshdAtMost(key string, limit int, zeroFails bool) func(*machine) (string, string) {
	return func(m *machine) (string, string) {
		if m.sshd == nil {
			return m.noSSH()
		}
		raw := strings.TrimSuffix(m.sshd[key], "s")
		value, err := strconv.Atoi(raw)
		if err != nil {
			return unknown("%s %q could not be read", key, m.sshd[key])
		}
		if (value == 0 && zeroFails) || value > limit {
			return fail("%s %d (from %s; expected 1 to %d)", key, value, m.sshdSource, limit)
		}
		return pass("%s %d (from %s)", key, value, m.sshdSource)
	}
}

func (m *machine) noSSH() (string, string) {
	if len(m.installed("openssh-server")) == 0 && m.anyActive("ssh", "sshd") == "" {
		return notApplicable("no SSH server is installed")
	}
	return unknown("the SSH server configuration could not be read")
}

// modeAtMost checks a file's permissions and that root owns it.
func modeAtMost(file string, limit int, optional bool) func(*machine) (string, string) {
	return func(m *machine) (string, string) {
		mode, found := m.modes[file]
		if !found {
			if optional {
				return notApplicable("%s does not exist", file)
			}
			return unknown("%s could not be read", file)
		}
		if mode.mode&^limit != 0 || mode.owner != "root" {
			return fail("%s is %04o, owned by %s:%s (expected %04o or stricter, owned by root)", file, mode.mode, mode.owner, mode.group, limit)
		}
		return pass("%s is %04o, owned by %s:%s", file, mode.mode, mode.owner, mode.group)
	}
}

// listOrNone summarises found paths for evidence.
func listOrNone(found []string, limit int) string {
	if len(found) > limit {
		return strings.Join(found[:limit], ", ") + fmt.Sprintf(" and %d more", len(found)-limit)
	}
	return strings.Join(found, ", ")
}

// rootLines returns the lines of a root fact, or ok false without root.
func (m *machine) rootLines(name string) ([]string, bool) {
	if !m.root || !m.collected(name) {
		return nil, false
	}
	return lines([]byte(m.facts[name])), true
}

var baseline = []control{
	// Accounts and passwords.
	{id: "ACC-01", category: categoryAccounts, severity: "critical", title: "Only root has user ID 0",
		rationale:   "Any account with user ID 0 has full control of the machine; a second one is a classic backdoor.",
		remediation: "Give the other accounts their own user ID, or remove them: usermod -u NEW_ID NAME.",
		check: func(m *machine) (string, string) {
			var extra []string
			for _, entry := range m.passwd() {
				if entry.uid == 0 && entry.name != "root" {
					extra = append(extra, entry.name)
				}
			}
			if len(extra) > 0 {
				return fail("accounts with user ID 0 besides root: %s", strings.Join(extra, ", "))
			}
			if len(m.passwd()) == 0 {
				return unknown("/etc/passwd could not be read")
			}
			return pass("only root has user ID 0")
		}},
	{id: "ACC-02", category: categoryAccounts, severity: "critical", title: "No account has an empty password",
		rationale:   "An account with an empty password can be used by anyone who reaches a login prompt.",
		remediation: "Set a password or lock the account: passwd -l NAME.",
		check: func(m *machine) (string, string) {
			entries, ok := m.rootLines("shadow")
			if !ok {
				return unknown(needsRoot)
			}
			var empty []string
			for _, line := range entries {
				if fields := strings.Split(line, ":"); len(fields) >= 2 && fields[1] == "EMPTY" {
					empty = append(empty, fields[0])
				}
			}
			if len(empty) > 0 {
				return fail("accounts with an empty password: %s", strings.Join(empty, ", "))
			}
			return pass("every account has a password or is locked")
		}},
	{id: "ACC-03", category: categoryAccounts, severity: "low", title: "Passwords expire within a year",
		rationale:   "A maximum password age limits how long a leaked password stays useful.",
		remediation: "Set PASS_MAX_DAYS 365 or less in /etc/login.defs, and for existing users: chage --maxdays 365 NAME.",
		check: func(m *machine) (string, string) {
			value := keyValues(m.facts["login.defs"])["pass_max_days"]
			days, err := strconv.Atoi(value)
			if err != nil {
				return fail("PASS_MAX_DAYS is not set in /etc/login.defs")
			}
			if days > 365 || days < 0 {
				return fail("PASS_MAX_DAYS %d", days)
			}
			return pass("PASS_MAX_DAYS %d", days)
		}},
	{id: "ACC-04", category: categoryAccounts, severity: "medium", title: "Passwords need at least 12 characters",
		rationale:   "Short passwords are guessed quickly.",
		remediation: "Set minlen = 12 or more in /etc/security/pwquality.conf (install libpam-pwquality on Debian and Ubuntu).",
		check: func(m *machine) (string, string) {
			if minimum, err := strconv.Atoi(keyValues(m.facts["pwquality"])["minlen"]); err == nil {
				if minimum >= 12 {
					return pass("pwquality minlen = %d", minimum)
				}
				return fail("pwquality minlen = %d", minimum)
			}
			if minimum, err := strconv.Atoi(keyValues(m.facts["login.defs"])["pass_min_len"]); err == nil && minimum >= 12 {
				return pass("PASS_MIN_LEN %d", minimum)
			}
			return fail("no minimum password length of 12 is set in pwquality.conf or login.defs")
		}},
	{id: "ACC-05", category: categoryAccounts, severity: "medium", title: "Accounts lock after repeated failed logins",
		rationale:   "Locking an account after a few failures stops password guessing on local and console logins.",
		remediation: "Enable pam_faillock (authselect enable-feature with-faillock on RHEL; pam-auth-update on Debian and Ubuntu).",
		check: func(m *machine) (string, string) {
			text := m.facts["pam"]
			if strings.Contains(text, "pam_faillock") || strings.Contains(text, "pam_tally2") {
				return pass("pam_faillock or pam_tally2 is configured in /etc/pam.d")
			}
			return fail("neither pam_faillock nor pam_tally2 is configured in /etc/pam.d")
		}},
	{id: "ACC-06", category: categoryAccounts, severity: "low", title: "New files are not readable by everyone",
		rationale:   "A default umask of 027 keeps files users create from being readable by all other accounts.",
		remediation: "Set UMASK 027 in /etc/login.defs.",
		check: func(m *machine) (string, string) {
			value := keyValues(m.facts["login.defs"])["umask"]
			umask, err := strconv.ParseInt(value, 8, 32)
			if err != nil {
				return fail("UMASK is not set in /etc/login.defs")
			}
			if umask&0o027 != 0o027 {
				return fail("UMASK %s (expected 027 or stricter)", value)
			}
			return pass("UMASK %s", value)
		}},
	{id: "ACC-07", category: categoryAccounts, severity: "medium", title: "System accounts cannot log in",
		rationale:   "Service accounts with a login shell can be used to get a shell if their password or key leaks.",
		remediation: "Give them a non-login shell: usermod -s /usr/sbin/nologin NAME.",
		check: func(m *machine) (string, string) {
			var found []string
			for _, entry := range m.passwd() {
				if entry.uid > 0 && entry.uid < 1000 && loginShell(entry.shell) {
					found = append(found, entry.name+" ("+entry.shell+")")
				}
			}
			if len(found) > 0 {
				return fail("system accounts with a login shell: %s", listOrNone(found, 8))
			}
			return pass("no system account has a login shell")
		}},
	{id: "ACC-08", category: categoryAccounts, severity: "medium", title: "Every account has its own user ID",
		rationale:   "Shared user IDs make files and audit records impossible to attribute to one account.",
		remediation: "Give each account a unique user ID with usermod -u.",
		check: func(m *machine) (string, string) {
			seen := map[int][]string{}
			for _, entry := range m.passwd() {
				seen[entry.uid] = append(seen[entry.uid], entry.name)
			}
			var shared []string
			for uid, names := range seen {
				if len(names) > 1 {
					shared = append(shared, fmt.Sprintf("%d: %s", uid, strings.Join(names, ", ")))
				}
			}
			if len(shared) > 0 {
				return fail("user IDs shared by several accounts: %s", strings.Join(shared, "; "))
			}
			return pass("no user ID is shared")
		}},
	{id: "ACC-09", category: categoryAccounts, severity: "low", title: "Unused accounts are locked after 90 days",
		rationale:   "Accounts nobody uses anymore, often of people who left, are easy to take over unnoticed.",
		remediation: "Set INACTIVE=35 (or at most 90) in /etc/default/useradd, and for existing accounts: chage --inactive 35 NAME.",
		check: func(m *machine) (string, string) {
			value := keyValues(m.facts["useradd"])["inactive"]
			days, err := strconv.Atoi(value)
			if err != nil || days < 0 {
				return fail("INACTIVE is not set in /etc/default/useradd, so unused accounts never lock")
			}
			if days > 90 {
				return fail("INACTIVE=%d", days)
			}
			return pass("INACTIVE=%d", days)
		}},
	{id: "ACC-10", category: categoryAccounts, severity: "medium", title: "Passwords can't reuse the last 4",
		rationale:   "Without a history, people cycle back to an old, possibly leaked password.",
		remediation: "Add remember=4 (or more) to pam_pwhistory or pam_unix in the PAM password stack.",
		check: func(m *machine) (string, string) {
			best := 0
			for _, line := range lines([]byte(m.facts["pam"])) {
				if !strings.Contains(line, "pam_pwhistory") && !strings.Contains(line, "pam_unix") {
					continue
				}
				for _, field := range strings.Fields(line) {
					if value, found := strings.CutPrefix(field, "remember="); found {
						if remember, err := strconv.Atoi(value); err == nil && remember > best {
							best = remember
						}
					}
				}
			}
			if best >= 4 {
				return pass("remember=%d", best)
			}
			if best > 0 {
				return fail("remember=%d", best)
			}
			return fail("no password history is configured in /etc/pam.d")
		}},
	{id: "ACC-11", category: categoryAccounts, severity: "medium", title: "Accounts lock after at most 10 failed logins",
		rationale:   "A high limit leaves room for thousands of guesses a day.",
		remediation: "Set deny = 10 or lower in /etc/security/faillock.conf.",
		check: func(m *machine) (string, string) {
			if !strings.Contains(m.facts["pam"], "pam_faillock") && !strings.Contains(m.facts["pam"], "pam_tally2") {
				return notApplicable("no lockout is configured; see ACC-05")
			}
			deny := 3 // pam_faillock's default
			source := "pam_faillock's default"
			if value, err := strconv.Atoi(keyValues(m.facts["faillock"])["deny"]); err == nil {
				deny, source = value, "/etc/security/faillock.conf"
			}
			for _, field := range strings.Fields(m.facts["pam"]) {
				if value, found := strings.CutPrefix(field, "deny="); found {
					if parsed, err := strconv.Atoi(value); err == nil {
						deny, source = parsed, "/etc/pam.d"
					}
				}
			}
			if deny == 0 || deny > 10 {
				return fail("deny = %d (from %s)", deny, source)
			}
			return pass("deny = %d (from %s)", deny, source)
		}},

	// SSH.
	{id: "SSH-01", category: categorySSH, severity: "high", title: "Root cannot log in over SSH with a password",
		rationale:   "Password logins as root let attackers guess the most powerful password directly.",
		remediation: "Set PermitRootLogin no (or prohibit-password) in /etc/ssh/sshd_config and reload sshd.",
		check:       sshdIs("permitrootlogin", "no", "prohibit-password", "without-password", "forced-commands-only")},
	{id: "SSH-02", category: categorySSH, severity: "medium", title: "SSH password logins are off",
		rationale:   "Keys can't be brute-forced; passwords can.",
		remediation: "Set PasswordAuthentication no in /etc/ssh/sshd_config after confirming key logins work.",
		check:       sshdIs("passwordauthentication", "no")},
	{id: "SSH-03", category: categorySSH, severity: "critical", title: "SSH refuses empty passwords",
		rationale:   "PermitEmptyPasswords yes lets anyone log in to an account without a password.",
		remediation: "Set PermitEmptyPasswords no.",
		check:       sshdIs("permitemptypasswords", "no")},
	{id: "SSH-04", category: categorySSH, severity: "low", title: "SSH X11 forwarding is off",
		rationale:   "Servers rarely need X11, and forwarding it widens what a compromised client can reach.",
		remediation: "Set X11Forwarding no.",
		check:       sshdIs("x11forwarding", "no")},
	{id: "SSH-05", category: categorySSH, severity: "low", title: "SSH allows at most 4 login attempts per connection",
		rationale:   "Fewer attempts per connection slow down password guessing.",
		remediation: "Set MaxAuthTries 4.",
		check:       sshdAtMost("maxauthtries", 4, false)},
	{id: "SSH-06", category: categorySSH, severity: "low", title: "Idle SSH sessions are closed",
		rationale:   "Abandoned sessions left open can be taken over at an unattended terminal.",
		remediation: "Set ClientAliveInterval 300 and ClientAliveCountMax 3.",
		check:       sshdAtMost("clientaliveinterval", 900, true)},
	{id: "SSH-07", category: categorySSH, severity: "medium", title: "SSH host-based authentication is off",
		rationale:   "Host-based trust lets one compromised machine log in to others without a password or key.",
		remediation: "Set HostbasedAuthentication no.",
		check:       sshdIs("hostbasedauthentication", "no")},
	{id: "SSH-08", category: categorySSH, severity: "medium", title: "SSH ignores .rhosts files",
		rationale:   ".rhosts files are a legacy trust mechanism that bypasses authentication.",
		remediation: "Set IgnoreRhosts yes.",
		check:       sshdIs("ignorerhosts", "yes")},
	{id: "SSH-09", category: categorySSH, severity: "low", title: "SSH logins must finish within a minute",
		rationale:   "A short login grace time limits unauthenticated connections tying up the server.",
		remediation: "Set LoginGraceTime 60.",
		check:       sshdAtMost("logingracetime", 60, true)},
	{id: "SSH-10", category: categorySSH, severity: "low", title: "Users cannot pass environment settings to SSH",
		rationale:   "PermitUserEnvironment can let users change how sshd starts their session, bypassing restrictions.",
		remediation: "Set PermitUserEnvironment no.",
		check:       sshdIs("permituserenvironment", "no")},
	{id: "SSH-11", category: categorySSH, severity: "medium", title: "SSH uses no weak ciphers or MACs",
		rationale:   "CBC-mode ciphers, RC4 and MD5 or 96-bit MACs have known weaknesses.",
		remediation: "Remove them from the Ciphers and MACs lines in sshd_config, or leave both unset to use OpenSSH's defaults.",
		check: func(m *machine) (string, string) {
			if m.sshd == nil {
				return m.noSSH()
			}
			var weak []string
			for _, key := range []string{"ciphers", "macs"} {
				for _, name := range strings.Split(m.sshd[key], ",") {
					if strings.Contains(name, "-cbc") || strings.Contains(name, "arcfour") || strings.Contains(name, "md5") || strings.Contains(name, "-96") {
						weak = append(weak, name)
					}
				}
			}
			if len(weak) > 0 {
				return fail("weak algorithms allowed: %s (from %s)", strings.Join(weak, ", "), m.sshdSource)
			}
			if m.sshdSource != "sshd -T" && m.sshd["ciphers"] == "" && m.sshd["macs"] == "" {
				return pass("Ciphers and MACs are not set, so OpenSSH's defaults apply")
			}
			return pass("no weak ciphers or MACs (from %s)", m.sshdSource)
		}},
	{id: "SSH-12", category: categorySSH, severity: "medium", title: "Only root can read the SSH server configuration",
		rationale:   "The configuration reveals how the server is protected; only root needs it.",
		remediation: "chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config.",
		check: func(m *machine) (string, string) {
			if _, found := m.modes["/etc/ssh/sshd_config"]; !found {
				return m.noSSH()
			}
			return modeAtMost("/etc/ssh/sshd_config", 0o600, false)(m)
		}},
	{id: "SSH-13", category: categorySSH, severity: "low", title: "SSH shows a warning banner before login",
		rationale:   "A banner states that access is restricted and monitored, which many policies and some laws require.",
		remediation: "Write the notice to /etc/issue.net and set Banner /etc/issue.net.",
		check: func(m *machine) (string, string) {
			if m.sshd == nil {
				return m.noSSH()
			}
			if banner := m.sshd["banner"]; banner != "" && banner != "none" {
				return pass("Banner %s (from %s)", banner, m.sshdSource)
			}
			return fail("no Banner is set (from %s)", m.sshdSource)
		}},
	{id: "SSH-14", category: categorySSH, severity: "low", title: "SSH logs every login",
		rationale:   "Login records are the first thing looked at after an incident.",
		remediation: "Set LogLevel INFO or VERBOSE.",
		check:       sshdIs("loglevel", "info", "verbose")},

	// Network.
	{id: "NET-01", category: categoryNetwork, severity: "medium", title: "IP forwarding is off",
		rationale:   "A machine that forwards packets can route traffic between networks it shouldn't connect.",
		remediation: "Set net.ipv4.ip_forward = 0 in /etc/sysctl.d/ and run sysctl --system.",
		check: func(m *machine) (string, string) {
			if host := m.forwardingHost(); host != "" {
				return notApplicable("this machine runs containers or VMs (%s), which need forwarding", host)
			}
			return sysctlIs("net.ipv4.ip_forward", "0")(m)
		}},
	{id: "NET-02", category: categoryNetwork, severity: "low", title: "ICMP redirects are not accepted",
		rationale:   "Redirects let another machine on the network change this one's routes.",
		remediation: "Set net.ipv4.conf.all.accept_redirects = 0 and net.ipv4.conf.default.accept_redirects = 0.",
		check:       sysctlIs("net.ipv4.conf.all.accept_redirects", "0")},
	{id: "NET-03", category: categoryNetwork, severity: "low", title: "ICMP redirects are not sent",
		rationale:   "Only routers should send redirects.",
		remediation: "Set net.ipv4.conf.all.send_redirects = 0.",
		check: func(m *machine) (string, string) {
			if host := m.forwardingHost(); host != "" {
				return notApplicable("this machine runs containers or VMs (%s)", host)
			}
			return sysctlIs("net.ipv4.conf.all.send_redirects", "0")(m)
		}},
	{id: "NET-04", category: categoryNetwork, severity: "medium", title: "Source-routed packets are refused",
		rationale:   "Source routing lets a sender choose the path, which helps bypass network controls.",
		remediation: "Set net.ipv4.conf.all.accept_source_route = 0.",
		check:       sysctlIs("net.ipv4.conf.all.accept_source_route", "0")},
	{id: "NET-05", category: categoryNetwork, severity: "low", title: "Reverse path filtering is on",
		rationale:   "It drops packets with spoofed source addresses.",
		remediation: "Set net.ipv4.conf.all.rp_filter = 1 (or 2 on machines with several routes).",
		check:       sysctlIs("net.ipv4.conf.all.rp_filter", "1", "2")},
	{id: "NET-06", category: categoryNetwork, severity: "low", title: "SYN cookies are on",
		rationale:   "SYN cookies keep the machine reachable during a SYN flood.",
		remediation: "Set net.ipv4.tcp_syncookies = 1.",
		check:       sysctlIs("net.ipv4.tcp_syncookies", "1")},
	{id: "NET-07", category: categoryNetwork, severity: "low", title: "Broadcast pings are ignored",
		rationale:   "Answering broadcast pings lets the machine be used in amplification attacks.",
		remediation: "Set net.ipv4.icmp_echo_ignore_broadcasts = 1.",
		check:       sysctlIs("net.ipv4.icmp_echo_ignore_broadcasts", "1")},
	{id: "NET-08", category: categoryNetwork, severity: "low", title: "Impossible source addresses are logged",
		rationale:   "Logging martian packets helps notice spoofing and misconfigured networks.",
		remediation: "Set net.ipv4.conf.all.log_martians = 1.",
		check:       sysctlIs("net.ipv4.conf.all.log_martians", "1")},
	{id: "NET-09", category: categoryNetwork, severity: "low", title: "IPv6 redirects are not accepted",
		rationale:   "As with IPv4, redirects let another machine change this one's routes.",
		remediation: "Set net.ipv6.conf.all.accept_redirects = 0.",
		check:       sysctlIs("net.ipv6.conf.all.accept_redirects", "0")},

	// Kernel.
	{id: "KRN-01", category: categoryKernel, severity: "high", title: "Address space layout randomisation is fully on",
		rationale:   "Randomising memory addresses makes memory-corruption exploits much harder.",
		remediation: "Set kernel.randomize_va_space = 2.",
		check:       sysctlIs("kernel.randomize_va_space", "2")},
	{id: "KRN-02", category: categoryKernel, severity: "low", title: "Only root can read the kernel log",
		rationale:   "The kernel log can reveal addresses and details useful to an attacker.",
		remediation: "Set kernel.dmesg_restrict = 1.",
		check:       sysctlIs("kernel.dmesg_restrict", "1")},
	{id: "KRN-03", category: categoryKernel, severity: "low", title: "Kernel addresses are hidden",
		rationale:   "Kernel pointers in /proc help attackers defeat address randomisation.",
		remediation: "Set kernel.kptr_restrict = 1 or 2.",
		check:       sysctlIs("kernel.kptr_restrict", "1", "2")},
	{id: "KRN-04", category: categoryKernel, severity: "low", title: "Processes cannot trace unrelated processes",
		rationale:   "Restricting ptrace stops a compromised process from reading other processes' memory.",
		remediation: "Set kernel.yama.ptrace_scope = 1 or higher.",
		check:       sysctlIs("kernel.yama.ptrace_scope", "1", "2", "3")},
	{id: "KRN-05", category: categoryKernel, severity: "medium", title: "Privileged programs don't write core dumps",
		rationale:   "Core dumps of setuid programs can contain passwords and keys.",
		remediation: "Set fs.suid_dumpable = 0.",
		check:       sysctlIs("fs.suid_dumpable", "0")},
	{id: "KRN-06", category: categoryKernel, severity: "medium", title: "Hard and symbolic link protection is on",
		rationale:   "It blocks a class of attacks that trick privileged programs through links in shared directories.",
		remediation: "Set fs.protected_hardlinks = 1 and fs.protected_symlinks = 1.",
		check: func(m *machine) (string, string) {
			hard, hardEvidence := sysctlIs("fs.protected_hardlinks", "1")(m)
			soft, softEvidence := sysctlIs("fs.protected_symlinks", "1")(m)
			switch {
			case hard == ControlFail || soft == ControlFail:
				return ControlFail, hardEvidence + "; " + softEvidence
			case hard == ControlPass && soft == ControlPass:
				return ControlPass, hardEvidence + "; " + softEvidence
			}
			return hard, hardEvidence
		}},
	{id: "KRN-07", category: categoryKernel, severity: "low", title: "Core dumps are off for everyone",
		rationale:   "A crashing program's memory can hold passwords and keys, written to disk for anyone who finds it.",
		remediation: "Add '* hard core 0' to /etc/security/limits.conf, and Storage=none to /etc/systemd/coredump.conf.",
		check: func(m *machine) (string, string) {
			text := m.facts["core-limits"]
			for _, line := range lines([]byte(text)) {
				fields := strings.Fields(line)
				if len(fields) == 4 && fields[0] == "*" && fields[1] == "hard" && fields[2] == "core" && fields[3] == "0" {
					return pass("* hard core 0 in the limits configuration")
				}
			}
			if strings.EqualFold(keyValues(text)["storage"], "none") {
				return pass("systemd-coredump Storage=none")
			}
			return fail("neither '* hard core 0' nor systemd-coredump Storage=none is set")
		}},

	// Services and firewall.
	{id: "SVC-01", category: categoryServices, severity: "medium", title: "A host firewall is active",
		rationale:   "A host firewall is a second layer behind the network's own, and still protects the machine if that is misconfigured.",
		remediation: "Enable ufw (Ubuntu, Debian) or firewalld (RHEL, Fedora, SUSE, Amazon Linux) and allow only the ports the machine serves.",
		check: func(m *machine) (string, string) {
			text, ok := m.rootLines("firewall")
			if !ok {
				return unknown(needsRoot)
			}
			result := Result{}
			checkFirewall(&result, []byte(strings.Join(text, "\n")))
			if len(result.Findings) > 0 {
				return fail("ufw, firewalld, nftables and iptables have no blocking rules")
			}
			return pass("blocking firewall rules are active")
		}},
	{id: "SVC-02", category: categoryServices, severity: "high", title: "No risky service listens on every interface",
		rationale:   "Databases, caches and remote shells reachable from other machines are frequent targets.",
		remediation: "Bind the service to 127.0.0.1 or a private address, or block its port.",
		check: func(m *machine) (string, string) {
			if !m.collected("listening") || strings.Contains(m.facts["listening"], noSocketTool) {
				return unknown("listening services could not be listed (neither ss nor netstat is installed)")
			}
			var risky []string
			for _, socket := range listening(m.facts["listening"]) {
				if service, found := exposedServices[socket.Port]; found && socket.Exposed {
					risky = append(risky, fmt.Sprintf("%s on %s port %d", service.name, strings.ToUpper(socket.Protocol), socket.Port))
				}
			}
			if len(risky) > 0 {
				return fail("listening on all interfaces: %s", strings.Join(risky, ", "))
			}
			return pass("no database, cache or remote shell listens on all interfaces")
		}},
	{id: "SVC-03", category: categoryServices, severity: "high", title: "No legacy remote-access servers are installed",
		rationale:   "Telnet, rsh, rlogin and TFTP send passwords and data unencrypted.",
		remediation: "Remove them, for example: apt purge telnetd or dnf remove telnet-server.",
		check: func(m *machine) (string, string) {
			if found := m.installed("telnetd", "inetutils-telnetd", "telnet-server", "rsh-server", "rsh-redone-server",
				"tftpd-hpa", "tftp-server", "nis", "ypserv"); len(found) > 0 {
				return fail("installed: %s", strings.Join(found, ", "))
			}
			if len(m.packages) == 0 {
				return unknown("the package list could not be read")
			}
			return pass("no telnet, rsh, TFTP or NIS server is installed")
		}},
	{id: "SVC-04", category: categoryServices, severity: "low", title: "No graphical desktop server is installed",
		rationale:   "A server rarely needs X, which adds a large amount of code to keep patched.",
		remediation: "Remove the X server packages (xserver-xorg or xorg-x11-server-Xorg).",
		check: func(m *machine) (string, string) {
			if found := m.installed("xserver-xorg", "xserver-xorg-core", "xorg-x11-server-Xorg"); len(found) > 0 {
				return fail("installed: %s", strings.Join(found, ", "))
			}
			return pass("no X server is installed")
		}},
	{id: "SVC-05", category: categoryServices, severity: "low", title: "Printing and service discovery are not running",
		rationale:   "CUPS and Avahi are desktop services that open ports a server doesn't need.",
		remediation: "systemctl disable --now cups avahi-daemon.",
		check: func(m *machine) (string, string) {
			var running []string
			for _, name := range []string{"cups", "avahi-daemon"} {
				if m.active[name] {
					running = append(running, name)
				}
			}
			if len(running) > 0 {
				return fail("running: %s", strings.Join(running, ", "))
			}
			return pass("CUPS and Avahi are not running")
		}},
	{id: "SVC-06", category: categoryServices, severity: "medium", title: "The mail server only accepts local mail",
		rationale:   "A mail server listening on every interface can be abused to relay spam.",
		remediation: "Set inet_interfaces = loopback-only in /etc/postfix/main.cf, or the equivalent for your mail server.",
		check: func(m *machine) (string, string) {
			for _, socket := range listening(m.facts["listening"]) {
				if socket.Port == 25 && socket.Protocol == "tcp" {
					if socket.Exposed {
						return fail("port 25 listens on %s", socket.Address)
					}
					return pass("port 25 listens on %s only", socket.Address)
				}
			}
			return notApplicable("no mail server listens on port 25")
		}},
	{id: "SVC-07", category: categoryServices, severity: "low", title: "USB storage can't be used",
		rationale:   "USB drives are a way to copy data off a server, or to bring malware onto it.",
		remediation: "Add 'install usb-storage /bin/false' to a file in /etc/modprobe.d/.",
		check: func(m *machine) (string, string) {
			text := m.facts["usb-storage"]
			switch {
			case !m.collected("usb-storage"):
				return unknown("modprobe is not available")
			case strings.Contains(text, "/bin/false") || strings.Contains(text, "/bin/true"):
				return pass("usb-storage is disabled in modprobe.d")
			case strings.Contains(strings.ToLower(text), "not found"):
				return notApplicable("this kernel has no usb-storage module")
			}
			return fail("usb-storage would load")
		}},

	// Logging and auditing.
	{id: "LOG-01", category: categoryLogging, severity: "medium", title: "The audit daemon is running",
		rationale:   "auditd records security events such as logins, privilege use and changes to key files.",
		remediation: "Install and start it: apt install auditd or dnf install audit, then systemctl enable --now auditd.",
		check: func(m *machine) (string, string) {
			if m.active["auditd"] {
				return pass("auditd is running")
			}
			if len(m.installed("auditd", "audit")) > 0 {
				return fail("auditd is installed but not running")
			}
			return fail("auditd is not installed")
		}},
	{id: "LOG-02", category: categoryLogging, severity: "low", title: "Audit rules are loaded",
		rationale:   "Without rules, auditd records very little.",
		remediation: "Add rules in /etc/audit/rules.d/, for example the ones your distribution ships, then run augenrules --load.",
		check: func(m *machine) (string, string) {
			if !m.active["auditd"] {
				return notApplicable("auditd is not running")
			}
			rules, ok := m.rootLines("audit-rules")
			if !ok {
				return unknown(needsRoot)
			}
			if len(rules) == 0 || (len(rules) == 1 && strings.Contains(strings.ToLower(rules[0]), "no rules")) {
				return fail("auditctl -l lists no rules")
			}
			return pass("%d audit rules are loaded", len(rules))
		}},
	{id: "LOG-03", category: categoryLogging, severity: "medium", title: "System logs are collected",
		rationale:   "Logs are how incidents are noticed and investigated.",
		remediation: "Run rsyslog, or keep journald logs on disk (Storage=persistent).",
		check: func(m *machine) (string, string) {
			if name := m.anyActive("rsyslog", "syslog-ng"); name != "" {
				return pass("%s is running", name)
			}
			if m.active["systemd-journald"] {
				return pass("systemd-journald is running")
			}
			return fail("neither rsyslog, syslog-ng nor systemd-journald is running")
		}},
	{id: "LOG-04", category: categoryLogging, severity: "low", title: "Logs survive a reboot",
		rationale:   "Logs kept only in memory are lost on reboot, often exactly when they are needed.",
		remediation: "Set Storage=persistent in /etc/systemd/journald.conf, or run rsyslog writing to /var/log.",
		check: func(m *machine) (string, string) {
			if name := m.anyActive("rsyslog", "syslog-ng"); name != "" {
				return pass("%s writes logs to disk", name)
			}
			text := m.facts["journald"]
			if strings.Contains(strings.ToLower(keyValues(text)["storage"]), "persistent") || strings.Contains(text, "PERSISTENT_DIRECTORY") {
				return pass("journald stores logs on disk")
			}
			return fail("journald keeps logs in memory only, and no syslog service runs")
		}},
	{id: "LOG-05", category: categoryLogging, severity: "low", title: "Log files aren't readable by everyone",
		rationale:   "Logs often contain user names, addresses and sometimes secrets typed in the wrong place.",
		remediation: "Remove read access for others: chmod o-r FILE, and fix the program or logrotate setting that creates it.",
		check: func(m *machine) (string, string) {
			found, ok := m.rootLines("readable-logs")
			if !ok {
				return unknown(needsRoot)
			}
			if len(found) > 0 {
				return fail("%d readable by everyone: %s", len(found), listOrNone(found, 5))
			}
			return pass("no file in /var/log is readable by everyone")
		}},

	// Files and permissions.
	{id: "FS-01", category: categoryFiles, severity: "high", title: "/etc/passwd is protected",
		rationale:   "Anyone who can change /etc/passwd can give themselves root.",
		remediation: "chown root:root /etc/passwd && chmod 644 /etc/passwd.",
		check:       modeAtMost("/etc/passwd", 0o644, false)},
	{id: "FS-02", category: categoryFiles, severity: "critical", title: "/etc/shadow is protected",
		rationale:   "/etc/shadow holds the password hashes, which can be cracked offline if read.",
		remediation: "chown root:root /etc/shadow (root:shadow on Debian and Ubuntu) && chmod 640 /etc/shadow.",
		check:       modeAtMost("/etc/shadow", 0o640, false)},
	{id: "FS-03", category: categoryFiles, severity: "medium", title: "/etc/group is protected",
		rationale:   "Anyone who can change /etc/group can add themselves to the administrators.",
		remediation: "chown root:root /etc/group && chmod 644 /etc/group.",
		check:       modeAtMost("/etc/group", 0o644, false)},
	{id: "FS-04", category: categoryFiles, severity: "medium", title: "/etc/gshadow is protected",
		rationale:   "It holds group password hashes.",
		remediation: "chown root:root /etc/gshadow (root:shadow on Debian and Ubuntu) && chmod 640 /etc/gshadow.",
		check:       modeAtMost("/etc/gshadow", 0o640, true)},
	{id: "FS-05", category: categoryFiles, severity: "low", title: "Only root can change scheduled jobs",
		rationale:   "Writable cron files let any account run commands as root on a schedule.",
		remediation: "chmod 600 /etc/crontab && chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly.",
		check: func(m *machine) (string, string) {
			var loose, checked []string
			for _, file := range []string{"/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"} {
				mode, found := m.modes[file]
				if !found {
					continue
				}
				checked = append(checked, file)
				if mode.mode&0o022 != 0 || mode.owner != "root" {
					loose = append(loose, fmt.Sprintf("%s %04o %s", file, mode.mode, mode.owner))
				}
			}
			if len(checked) == 0 {
				return notApplicable("no cron files exist")
			}
			if len(loose) > 0 {
				return fail("writable by others than root: %s", strings.Join(loose, ", "))
			}
			return pass("%d cron files and directories are writable by root only", len(checked))
		}},
	{id: "FS-06", category: categoryFiles, severity: "low", title: "/tmp is mounted nodev and nosuid",
		rationale:   "Device files and setuid programs in /tmp, which everyone can write, are a common escalation path.",
		remediation: "Mount /tmp separately (for example systemctl enable tmp.mount) with the nodev and nosuid options.",
		check:       mountHas("/tmp", "nodev", "nosuid")},
	{id: "FS-07", category: categoryFiles, severity: "low", title: "/dev/shm is mounted nodev, nosuid and noexec",
		rationale:   "Shared memory is writable by everyone and is used to stage attack tools.",
		remediation: "Add nodev,nosuid,noexec to the /dev/shm entry in /etc/fstab and remount it.",
		check:       mountHas("/dev/shm", "nodev", "nosuid", "noexec")},
	{id: "FS-08", category: categoryFiles, severity: "medium", title: "No files are writable by everyone",
		rationale:   "A file anyone can change can be replaced with malicious content.",
		remediation: "Remove the write permission for others: chmod o-w FILE.",
		check: func(m *machine) (string, string) {
			found, ok := m.rootLines("world-writable")
			if !ok {
				return unknown(needsRoot)
			}
			var files []string
			for _, file := range found {
				if !strings.HasPrefix(file, "/proc/") && !strings.HasPrefix(file, "/sys/") {
					files = append(files, file)
				}
			}
			if len(files) > 0 {
				return fail("%d writable by everyone: %s", len(files), listOrNone(files, 5))
			}
			return pass("no file is writable by everyone")
		}},
	{id: "FS-09", category: categoryFiles, severity: "medium", title: "Shared directories have the sticky bit",
		rationale:   "Without it, anyone can delete or replace other users' files in a directory everyone can write.",
		remediation: "chmod +t DIRECTORY.",
		check: func(m *machine) (string, string) {
			found, ok := m.rootLines("unsticky")
			if !ok {
				return unknown(needsRoot)
			}
			if len(found) > 0 {
				return fail("%d without the sticky bit: %s", len(found), listOrNone(found, 5))
			}
			return pass("every directory anyone can write has the sticky bit")
		}},
	{id: "FS-10", category: categoryFiles, severity: "low", title: "Every file has an owner",
		rationale:   "Files left by deleted accounts are taken over by whoever gets that user ID next.",
		remediation: "Give them an owner with chown, or remove them.",
		check: func(m *machine) (string, string) {
			found, ok := m.rootLines("unowned")
			if !ok {
				return unknown(needsRoot)
			}
			if len(found) > 0 {
				return fail("%d without an owner: %s", len(found), listOrNone(found, 5))
			}
			return pass("every file has an owner and a group")
		}},
	{id: "FS-11", category: categoryFiles, severity: "medium", title: "No setuid programs outside system directories",
		rationale:   "A setuid program in an unusual place is a common way attackers keep root access.",
		remediation: "Check each one; remove the setuid bit (chmod u-s,g-s FILE) unless it is meant to be there.",
		check: func(m *machine) (string, string) {
			found, ok := m.rootLines("setid")
			if !ok {
				return unknown(needsRoot)
			}
			var unusual []string
			for _, file := range found {
				systemPath := false
				for _, prefix := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/snap/", "/opt/google/", "/var/lib/snapd/"} {
					systemPath = systemPath || strings.HasPrefix(file, prefix)
				}
				if !systemPath {
					unusual = append(unusual, file)
				}
			}
			if len(unusual) > 0 {
				return fail("%d outside system directories: %s", len(unusual), listOrNone(unusual, 5))
			}
			return pass("%d setuid or setgid programs, all in system directories", len(found))
		}},
	{id: "FS-12", category: categoryFiles, severity: "low", title: "Only root can read the boot loader configuration",
		rationale:   "The boot configuration can reveal or allow changing kernel options.",
		remediation: "chmod 600 /boot/grub/grub.cfg (or /boot/grub2/grub.cfg).",
		check: func(m *machine) (string, string) {
			for _, file := range []string{"/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"} {
				if _, found := m.modes[file]; found {
					return modeAtMost(file, 0o600, false)(m)
				}
			}
			return notApplicable("no GRUB configuration was found")
		}},
	{id: "FS-13", category: categoryFiles, severity: "low", title: "Home directories are private",
		rationale:   "Other accounts can read files left in a home directory that's open to them.",
		remediation: "chmod 750 /home/NAME (or 700).",
		check: func(m *machine) (string, string) {
			var open []string
			homes := 0
			for _, line := range lines([]byte(m.facts["homes"])) {
				fields := strings.Fields(line)
				if len(fields) != 3 {
					continue
				}
				mode, err := strconv.ParseInt(fields[0], 8, 32)
				if err != nil {
					continue
				}
				homes++
				if mode&0o027 != 0 {
					open = append(open, fmt.Sprintf("%s %04o", fields[2], mode))
				}
			}
			if homes == 0 {
				return notApplicable("there are no home directories in /home")
			}
			if len(open) > 0 {
				return fail("open to other accounts: %s", listOrNone(open, 5))
			}
			return pass("%d home directories are private", homes)
		}},

	// Updates.
	{id: "UPD-01", category: categoryUpdates, severity: "medium", title: "Security updates install automatically",
		rationale:   "Fixes that wait for someone to apply them leave the machine exposed for longer.",
		remediation: "Enable unattended-upgrades (Debian, Ubuntu), dnf-automatic (RHEL and its rebuilds, Fedora, Amazon Linux) or os-update (SUSE).",
		check: func(m *machine) (string, string) {
			text := m.facts["auto-updates"]
			for _, line := range lines([]byte(text)) {
				if (strings.Contains(line, "Unattended-Upgrade") && strings.Contains(line, `"1"`)) || strings.TrimSpace(line) == "enabled" {
					return pass("automatic updates are enabled")
				}
			}
			return fail("none of unattended-upgrades, dnf-automatic and os-update is enabled")
		}},
	{id: "UPD-02", category: categoryUpdates, severity: "medium", title: "No reboot is pending to finish updates",
		rationale:   "Updated kernels and libraries only take effect after a reboot; until then the old code runs.",
		remediation: "Reboot the machine at a convenient time.",
		check: func(m *machine) (string, string) {
			text := m.facts["reboot"]
			if strings.Contains(text, "REBOOT_REQUIRED") || strings.Contains(text, "NEEDS_RESTARTING 1") {
				return fail("updates are waiting for a reboot")
			}
			return pass("no reboot is pending")
		}},
	{id: "UPD-03", category: categoryUpdates, severity: "medium", title: "Packages are only installed from signed sources",
		rationale:   "Unsigned packages could be replaced in transit or on a mirror without anyone noticing.",
		remediation: "Set gpgcheck=1 for every repository (RHEL, Fedora, SUSE, Amazon Linux); remove trusted=yes and AllowUnauthenticated from APT's configuration.",
		check: func(m *machine) (string, string) {
			var unsigned []string
			for _, line := range lines([]byte(m.facts["package-signing"])) {
				compact := strings.ToLower(strings.Join(strings.Fields(line), ""))
				if compact == "gpgcheck=0" || compact == "gpgcheck=false" || strings.Contains(compact, "trusted=yes") ||
					strings.Contains(compact, "allowunauthenticated\"true\"") || strings.Contains(compact, "allow-insecure=yes") {
					unsigned = append(unsigned, strings.TrimSpace(line))
				}
			}
			if len(unsigned) > 0 {
				return fail("signatures are turned off: %s", listOrNone(unsigned, 3))
			}
			return pass("no repository turns package signatures off")
		}},

	// Time.
	{id: "TIME-01", category: categoryTime, severity: "medium", title: "Time synchronisation is running",
		rationale:   "Accurate time keeps logs comparable across machines and certificates and tokens valid.",
		remediation: "Enable chrony or systemd-timesyncd.",
		check: func(m *machine) (string, string) {
			if name := m.anyActive("chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp", "ntpsec"); name != "" {
				return pass("%s is running", name)
			}
			return fail("no time synchronisation service is running")
		}},
	{id: "TIME-02", category: categoryTime, severity: "low", title: "The clock is synchronised",
		rationale:   "A running service that cannot reach a time server leaves the clock drifting.",
		remediation: "Check that the time servers are reachable: chronyc sources or timedatectl timesync-status.",
		check: func(m *machine) (string, string) {
			values := keyValues(m.facts["time"])
			switch values["ntpsynchronized"] {
			case "yes":
				return pass("NTPSynchronized=yes")
			case "no":
				return fail("NTPSynchronized=no")
			}
			return unknown("timedatectl is not available")
		}},

	// Mandatory access control.
	{id: "MAC-01", category: categoryProtection, severity: "medium", title: "AppArmor or SELinux is enforcing",
		rationale:   "Mandatory access control confines services, so a compromised one can do far less.",
		remediation: "Keep AppArmor enabled (Debian, Ubuntu, SUSE) or set SELINUX=enforcing (RHEL and its rebuilds, Fedora, Amazon Linux).",
		check: func(m *machine) (string, string) {
			if strings.TrimSpace(m.facts["selinux"]) == "1" {
				return pass("SELinux is enforcing")
			}
			if strings.TrimSpace(m.facts["apparmor"]) == "Y" {
				return pass("AppArmor is enabled")
			}
			if strings.TrimSpace(m.facts["selinux"]) == "0" {
				return fail("SELinux is in permissive mode")
			}
			return fail("neither AppArmor nor SELinux is enabled")
		}},
}

// mountHas checks that a mount point exists with the given options.
func mountHas(mountPoint string, options ...string) func(*machine) (string, string) {
	return func(m *machine) (string, string) {
		if !m.collected("mounts") {
			return unknown("the mounts could not be read")
		}
		for _, line := range lines([]byte(m.facts["mounts"])) {
			fields := strings.Fields(line)
			if len(fields) < 4 || path.Clean(fields[1]) != mountPoint {
				continue
			}
			have := map[string]bool{}
			for _, option := range strings.Split(fields[3], ",") {
				have[option] = true
			}
			var missing []string
			for _, option := range options {
				if !have[option] {
					missing = append(missing, option)
				}
			}
			if len(missing) > 0 {
				return fail("%s is mounted without %s", mountPoint, strings.Join(missing, ", "))
			}
			return pass("%s is mounted with %s", mountPoint, strings.Join(options, ", "))
		}
		return fail("%s is not a separate mount", mountPoint)
	}
}

// BaselineIDs lists the baseline's control IDs.
func BaselineIDs() []string {
	ids := make([]string, 0, len(baseline)+len(macBaseline))
	for _, control := range baseline {
		ids = append(ids, control.id)
	}
	// The macOS baseline's controls are accepted and mapped the same way.
	for _, item := range macBaseline {
		ids = append(ids, item.id)
	}
	return ids
}

// BaselineSize is how many controls the baseline has.
func BaselineSize() int { return len(baseline) }
