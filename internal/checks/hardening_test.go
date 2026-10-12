package checks

import (
	"strings"
	"testing"
	"time"

	"deaconguard/internal/platform"
)

// factOutput prints facts as the facts script does.
func factOutput(facts map[string]string) string {
	var builder strings.Builder
	for name, value := range facts {
		builder.WriteString(factMarker + name + " @@\n" + value + "\n")
	}
	return builder.String()
}

// runAudit runs the hardening check as root against canned facts.
func runAudit(t *testing.T, user, root map[string]string) (Result, map[string]ControlResult) {
	t.Helper()
	host := &fakeHost{answers: map[string]fakeAnswer{
		script(userFacts): {output: factOutput(user)},
		script(rootFacts): {output: factOutput(root)},
	}}
	executor := NewExecutor(host, true, nil)
	executor.AsRoot()
	result := Run(Hardening, executor, platform.Platform{Family: platform.Ubuntu}, time.Now(), Inputs{})
	byID := map[string]ControlResult{}
	for _, control := range result.Controls {
		byID[control.ID] = control
	}
	if len(result.Controls) != BaselineSize() {
		t.Fatalf("%d controls, want %d", len(result.Controls), BaselineSize())
	}
	return result, byID
}

func expect(t *testing.T, controls map[string]ControlResult, status string, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if got := controls[id]; got.Status != status {
			t.Errorf("%s = %s (%s), want %s", id, got.Status, got.Evidence, status)
		}
	}
}

func TestHardeningFindsAnInsecureMachine(t *testing.T) {
	result, controls := runAudit(t, map[string]string{
		"os":       "Ubuntu 24.04.1 LTS",
		"hostname": "ip-10-92-0-52",
		"passwd": "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/bin/sh\n" +
			"ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\nshared:x:1000:1000::/home/shared:/bin/bash",
		"login.defs": "PASS_MAX_DAYS 99999\nUMASK 022",
		"sshd-files": "==> /etc/ssh/sshd_config <==\nPermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\nCiphers aes128-cbc,aes256-gcm@openssh.com",
		"sysctl": "net.ipv4.ip_forward = 1\nkernel.randomize_va_space = 0\nnet.ipv4.conf.all.accept_redirects = 1",
		"modes":  "666 root root /etc/passwd\n644 root shadow /etc/shadow\n644 root root /etc/ssh/sshd_config",
		"packages": "openssh-server\ntelnetd\nauditd",
		"listening": "tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:25 0.0.0.0:*",
		"mounts":    "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0",
		"reboot":    "REBOOT_REQUIRED",
		"time":      "Timezone=UTC\nNTPSynchronized=no",
		"active-units": "auditd.service loaded active running Audit\ncups.service loaded active running CUPS",
		"apparmor":  "N",
	}, map[string]string{
		"shadow":         "root:SET:99999\nguest:EMPTY:99999",
		"firewall":       "Status: inactive",
		"setid":          "/usr/bin/sudo\n/home/ubuntu/.cache/backdoor",
		"world-writable": "/etc/app.conf",
		"audit-rules":    "No rules",
	})
	expect(t, controls, ControlFail,
		"ACC-01", "ACC-02", "ACC-03", "ACC-05", "ACC-06", "ACC-07", "ACC-08",
		"SSH-01", "SSH-02", "SSH-04", "SSH-11", "SSH-12",
		"NET-01", "NET-02", "KRN-01", "SVC-01", "SVC-02", "SVC-03", "SVC-05", "SVC-06",
		"LOG-02", "FS-01", "FS-02", "FS-06", "FS-07", "FS-08", "FS-11",
		"UPD-01", "UPD-02", "TIME-01", "TIME-02", "MAC-01")
	expect(t, controls, ControlPass, "SSH-03", "LOG-01")
	expect(t, controls, ControlNA, "FS-04")
	if result.Status != StatusCompleted || !result.Privileged {
		t.Fatalf("status %s, privileged %t", result.Status, result.Privileged)
	}
	if result.Inventory == nil || result.Inventory.OS != "Ubuntu 24.04.1 LTS" || result.Inventory.Hostname != "ip-10-92-0-52" {
		t.Fatalf("inventory = %+v", result.Inventory)
	}
	if !strings.Contains(controls["ACC-02"].Evidence, "guest") || strings.Contains(controls["ACC-02"].Evidence, "SET") {
		t.Fatalf("empty password evidence = %q", controls["ACC-02"].Evidence)
	}
	// Each failed control is also a finding, so the host's page lists it.
	failedCount := 0
	for _, control := range result.Controls {
		if control.Status == ControlFail {
			failedCount++
		}
	}
	if len(result.Findings) != failedCount {
		t.Fatalf("%d findings for %d failed controls", len(result.Findings), failedCount)
	}
}

func TestHardeningPassesAHardenedMachine(t *testing.T) {
	_, controls := runAudit(t, map[string]string{
		"passwd":     "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000::/home/admin:/bin/bash",
		"login.defs": "PASS_MAX_DAYS 90\nUMASK 027",
		"pwquality":  "minlen = 14",
		"pam":        "auth required pam_faillock.so preauth",
		"sysctl": "net.ipv4.ip_forward = 0\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.send_redirects = 0\n" +
			"net.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.all.log_martians = 1\n" +
			"net.ipv4.icmp_echo_ignore_broadcasts = 1\nnet.ipv4.tcp_syncookies = 1\nnet.ipv6.conf.all.accept_redirects = 0\n" +
			"kernel.randomize_va_space = 2\nkernel.dmesg_restrict = 1\nkernel.kptr_restrict = 1\nkernel.yama.ptrace_scope = 1\n" +
			"fs.suid_dumpable = 0\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1",
		"modes": "644 root root /etc/passwd\n640 root shadow /etc/shadow\n644 root root /etc/group\n640 root shadow /etc/gshadow\n" +
			"600 root root /etc/ssh/sshd_config\n600 root root /etc/crontab\n700 root root /etc/cron.d\n600 root root /boot/grub/grub.cfg",
		"packages":     "openssh-server\nauditd\nchrony",
		"listening":    "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 100 127.0.0.1:25 0.0.0.0:*",
		"mounts":       "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0",
		"auto-updates": `APT::Periodic::Unattended-Upgrade "1";`,
		"time":         "Timezone=Europe/London\nNTPSynchronized=yes",
		"active-units": "auditd.service loaded active running\nchrony.service loaded active running\nrsyslog.service loaded active running",
		"apparmor":     "Y",
		"reboot":       "",
	}, map[string]string{
		"shadow":         "root:SET:90\nadmin:SET:90",
		"sshd-effective": "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nx11forwarding no\nmaxauthtries 3\nclientaliveinterval 300\nhostbasedauthentication no\nignorerhosts yes\nlogingracetime 60\npermituserenvironment no\nciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\nmacs hmac-sha2-512-etm@openssh.com",
		"firewall":       "Status: active",
		"setid":          "/usr/bin/sudo\n/usr/bin/passwd",
		"world-writable": "",
		"unsticky":       "",
		"unowned":        "",
		"audit-rules":    "-w /etc/passwd -p wa -k identity",
	})
	for id, control := range controls {
		if control.Status == ControlFail || control.Status == ControlUnknown {
			t.Errorf("%s %s: %s", id, control.Status, control.Evidence)
		}
	}
}

func TestHardeningWithoutRootSaysWhatItCouldNotCheck(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{script(userFacts): {output: factOutput(map[string]string{
		"passwd": "root:x:0:0:root:/root:/bin/bash",
	})}}}
	result := Run(Hardening, NewExecutor(host, false, nil), platform.Platform{Family: platform.Debian}, time.Now(), Inputs{})
	if result.Status != StatusPartial || result.Privileged {
		t.Fatalf("status %s, privileged %t", result.Status, result.Privileged)
	}
	for _, control := range result.Controls {
		if control.ID == "ACC-02" && control.Status != ControlUnknown {
			t.Fatalf("ACC-02 without root = %s", control.Status)
		}
	}
	for _, command := range host.commands {
		if strings.Contains(command, "awk -F:") {
			t.Fatal("read the contents of /etc/shadow without being allowed root")
		}
	}
}

func TestFactSectionsRoundTrip(t *testing.T) {
	parsed := sections([]byte(factOutput(map[string]string{"a": "one\ntwo", "sshd-files": "==> /etc/ssh/sshd_config <==\nPort 22"})))
	if parsed["a"] != "one\ntwo" || !strings.Contains(parsed["sshd-files"], "==> /etc/ssh/sshd_config <==") {
		t.Fatalf("sections = %#v", parsed)
	}
}
