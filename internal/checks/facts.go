package checks

import (
	"strings"
	"time"
)

const factsTimeout = 3 * time.Minute

// A fact is one fixed, read-only command whose output the hardening check
// reads. Each runs in a section of one script, so the check costs a single
// command on the host.
type fact struct {
	name    string
	command string
}

// Facts any account can read.
var userFacts = []fact{
	{"os", "grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"'"},
	{"uname", "uname -srm"},
	{"hostname", "hostname"},
	{"uptime", "cat /proc/uptime"},
	{"cpus", "nproc"},
	{"memory", "grep -E '^MemTotal:' /proc/meminfo"},
	{"disks", "df -P -k -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs"},
	{"addresses", "ip -brief address"},
	{"virtualization", "systemd-detect-virt"},
	{"passwd", "cat /etc/passwd"},
	{"admins", "getent group sudo wheel admin"},
	{"login.defs", "cat /etc/login.defs"},
	{"pwquality", "cat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"},
	{"pam", "grep -rhE '^[^#]*(pam_faillock|pam_tally2|pam_pwquality|pam_cracklib)' /etc/pam.d"},
	{"sysctl", "sysctl " + strings.Join(sysctlKeys, " ")},
	{"mounts", "cat /proc/mounts"},
	{"modes", "stat -c '%a %U %G %n' /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/ssh/sshd_config " +
		"/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /boot/grub/grub.cfg /boot/grub2/grub.cfg"},
	{"active-units", "systemctl list-units --no-legend --no-pager --plain --type=service,socket,timer --state=active"},
	{"time", "timedatectl show"},
	{"packages", "if command -v dpkg-query >/dev/null; then dpkg-query -W -f='${Package} ${Status}\\n' | grep ' installed$' | cut -d' ' -f1; else rpm -qa --qf '%{NAME}\\n'; fi"},
	{"apparmor", "cat /sys/module/apparmor/parameters/enabled"},
	{"selinux", "cat /sys/fs/selinux/enforce"},
	{"listening", "if command -v ss >/dev/null; then ss -H -tuln; elif command -v netstat >/dev/null; then netstat -tuln; else echo " + noSocketTool + "; fi"},
	{"sshd-files", sshdConfigCommand},
	{"journald", "cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; test -d /var/log/journal && echo PERSISTENT_DIRECTORY"},
	{"reboot", "if [ -f /var/run/reboot-required ]; then echo REBOOT_REQUIRED; fi; if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1; echo \"NEEDS_RESTARTING $?\"; fi"},
	{"auto-updates", "cat /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -i 'Unattended-Upgrade\"'; systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer"},
}

// Facts that need root to be complete. Only the account names and whether a
// password is set leave /etc/shadow; password hashes never do.
var rootFacts = []fact{
	{"shadow", `awk -F: '{ print $1 ":" ($2 == "" ? "EMPTY" : "SET") ":" $5 }' /etc/shadow`},
	{"sshd-effective", "sshd -T"},
	{"firewall", "ufw status; firewall-cmd --state; nft list ruleset | head -n 2000; iptables -S | head -n 2000"},
	{"setid", "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | head -n 500"},
	{"world-writable", "find / -xdev -type f -perm -0002 | head -n 200"},
	{"unsticky", "find / -xdev -type d -perm -0002 ! -perm -1000 | head -n 200"},
	{"unowned", "find / -xdev \\( -nouser -o -nogroup \\) | head -n 200"},
	{"audit-rules", "auditctl -l | head -n 500"},
}

// noSocketTool marks a machine with neither ss nor netstat.
const noSocketTool = "NO_SOCKET_TOOL"

// sysctlKeys are the kernel settings the baseline reads.
var sysctlKeys = []string{
	"net.ipv4.ip_forward", "net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.all.log_martians", "net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.tcp_syncookies",
	"net.ipv6.conf.all.accept_redirects", "kernel.randomize_va_space", "kernel.dmesg_restrict", "kernel.kptr_restrict",
	"kernel.yama.ptrace_scope", "fs.suid_dumpable", "fs.protected_hardlinks", "fs.protected_symlinks",
}

// factMarker starts each fact's section. It differs from the "==> file <=="
// lines the SSH configuration fact prints itself.
const factMarker = "@@ deaconguard fact "

// script joins facts into one command that prints each output after a
// marker line. Errors are discarded: a missing tool just leaves its
// section empty.
func script(facts []fact) string {
	var builder strings.Builder
	for _, fact := range facts {
		builder.WriteString("printf '" + factMarker + "%s @@\\n' '" + fact.name + "'; ( " + fact.command + " ) 2>/dev/null; ")
	}
	builder.WriteString("true")
	return builder.String()
}

// sections splits a script's output back into its facts. A fact whose
// section is missing was not collected at all.
func sections(output []byte) map[string]string {
	result := make(map[string]string)
	current := ""
	var body []string
	flush := func() {
		if current != "" {
			result[current] = strings.Join(body, "\n")
		}
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, factMarker) && strings.HasSuffix(line, " @@") {
			flush()
			current, body = strings.TrimSuffix(strings.TrimPrefix(line, factMarker), " @@"), nil
			continue
		}
		if current != "" {
			body = append(body, line)
		}
	}
	flush()
	return result
}
