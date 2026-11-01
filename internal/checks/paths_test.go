package checks

import (
	"strings"
	"testing"
)

func pathFindings(result Result) map[string][]Finding {
	byRule := map[string][]Finding{}
	for _, finding := range result.Findings {
		byRule[finding.Rule] = append(byRule[finding.Rule], finding)
	}
	return byRule
}

func TestAttackPaths(t *testing.T) {
	facts := map[string]string{
		"sudoers": strings.Join([]string{
			"/etc/sudoers:Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/tools/bin\"",
			"/etc/sudoers:root\tALL=(ALL:ALL) ALL",
			"/etc/sudoers:%sudo\tALL=(ALL:ALL) ALL",
			"/etc/sudoers.d/90-cloud-init-users:ubuntu ALL=(ALL) NOPASSWD:ALL",
			"/etc/sudoers.d/ops:deploy ALL=(root) NOPASSWD: /usr/bin/vim /etc/nginx/nginx.conf, /usr/local/bin/restart-app",
			"/etc/sudoers.d/ops:backup ALL=(ALL) /usr/bin/python3.11",
			"/etc/sudoers.d/ops:web ALL=(postgres) NOPASSWD: /usr/bin/psql",
			"/etc/sudoers.d/ops:Cmnd_Alias RESTART = /bin/systemctl restart app",
		}, "\n"),
		"groups":       "docker:x:999:deploy,root\nlxd:x:998:\ndisk:x:6:",
		"sockets":      "666 0 999 root docker /var/run/docker.sock\n660 0 999 root docker /run/containerd/containerd.sock",
		"setuid":       "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/find\n/bin/find\n/usr/bin/su",
		"capabilities": "/usr/bin/ping cap_net_raw=ep\n/usr/bin/python3.11 cap_setuid=ep\n/usr/local/bin/backupd cap_dac_read_search=ep",
		"environment":  `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"`,
		"cron": strings.Join([]string{
			"/etc/crontab:SHELL=/bin/sh",
			"/etc/crontab:17 * * * * root cd / && run-parts --report /etc/cron.hourly",
			"/etc/cron.d/backup:0 3 * * * root /home/deploy/backup.sh --full",
			"/etc/cron.d/report:0 4 * * * deploy /home/deploy/report.sh",
			"/var/spool/cron/crontabs/root:@daily /opt/jobs/cleanup.sh",
			"/etc/cron.daily/logrotate:@script /etc/cron.daily/logrotate",
		}, "\n"),
		"units": strings.Join([]string{
			"Id=ssh.service", "User=", "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no }", "FragmentPath=/lib/systemd/system/ssh.service", "",
			"Id=app.service", "User=app", "ExecStart={ path=/srv/app/bin/app ; argv[]=/srv/app/bin/app ; }", "FragmentPath=/etc/systemd/system/app.service", "",
			"Id=agent.service", "User=", "ExecStart={ path=/opt/agent/run ; argv[]=/opt/agent/run ; }", "FragmentPath=/etc/systemd/system/agent.service",
		}, "\n"),
		"secrets": strings.Join([]string{
			"600 1000 1000 deploy deploy /home/deploy/.ssh/id_ed25519",
			"644 1000 1000 deploy deploy /home/deploy/.ssh/id_ed25519.pub",
			"644 1000 1000 deploy deploy /home/deploy/.ssh/authorized_keys",
			"644 1000 1000 deploy deploy /home/deploy/.ssh/id_rsa",
			"640 1000 1000 deploy deploy /home/deploy/.aws/credentials",
			"640 1000 50 deploy staff /home/deploy/.git-credentials",
			"644 33 33 www-data www-data /var/www/shop/.env",
			"640 33 33 www-data www-data /var/www/shop/.env.production",
			"644 33 33 www-data www-data /var/www/shop/.env.example",
			"640 0 0 root root /etc/ssh/ssh_host_ed25519_key",
			"644 0 0 root root /etc/ssh/ssh_host_rsa_key",
		}, "\n"),
		SectionKeys: "root 0 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop",
	}
	analysis := analysePaths(facts, true)
	stat := strings.Join(analysis.toStat(), "|")
	for _, want := range []string{"/usr/local/bin/restart-app", "/home/deploy/backup.sh", "/home/deploy", "/opt/jobs/cleanup.sh", "/etc/cron.daily/logrotate",
		"/opt/agent/run", "/etc/systemd/system/agent.service", "/etc/systemd/system/app.service", "/opt/tools/bin", "/usr/local/sbin"} {
		if !strings.Contains("|"+stat+"|", "|"+want+"|") {
			t.Errorf("not checked: %s in %s", want, stat)
		}
	}
	// Root runs neither another account's cron job nor a service as app.
	for _, unwanted := range []string{"/home/deploy/report.sh", "/srv/app/bin/app", "/usr/bin/psql", "/lib/systemd/system/ssh.service"} {
		if strings.Contains("|"+stat+"|", "|"+unwanted+"|") {
			t.Errorf("checked %s, which root doesn't run", unwanted)
		}
	}
	analysis.modes = map[string]permissions{}
	for _, line := range []string{
		"755 0 0 root root /usr/local/bin/restart-app",
		"755 1000 1000 deploy deploy /home/deploy/backup.sh",
		"750 1000 1000 deploy deploy /home/deploy",
		"755 0 0 root root /home",
		"755 0 0 root root /opt/jobs/cleanup.sh",
		"777 0 0 root root /opt/jobs",
		"755 0 0 root root /opt",
		"1777 0 0 root root /tmp",
		"755 0 0 root root /opt/agent/run",
		"775 0 1001 root ops /opt/agent",
		"644 0 0 root root /etc/systemd/system/agent.service",
		"2775 0 50 root staff /usr/local/sbin",
		"755 0 0 root root /opt/tools/bin",
	} {
		mode, ok := parsePermissions(line)
		if !ok {
			t.Fatalf("parse %q", line)
		}
		analysis.modes[mode.name] = mode
	}
	result := analysis.result()
	byRule := pathFindings(result)
	if result.Status != StatusCompleted || len(result.Keys) != 1 || !result.Keys[0].Root {
		t.Fatalf("result: %+v", result)
	}

	if got := byRule[RuleSudoAll]; len(got) != 1 || !strings.Contains(got[0].Title, "ubuntu") || got[0].Severity != "MEDIUM" {
		t.Errorf("sudo all: %+v", got)
	}
	shells := byRule[RuleSudoShell]
	if len(shells) != 2 || shells[0].Title != "sudo vim gives deploy a root shell" || shells[0].Severity != "HIGH" ||
		shells[1].Title != "sudo python3.11 gives backup a root shell" || shells[1].Severity != "MEDIUM" {
		t.Errorf("sudo shells: %+v", shells)
	}
	if strings.Join(shells[0].Path, " > ") != "deploy > sudo vim > root" {
		t.Errorf("path: %v", shells[0].Path)
	}
	if got := byRule[RuleRootGroup]; len(got) != 1 || got[0].Title != "deploy is in the docker group, which is root" {
		t.Errorf("groups: %+v", got)
	}
	if got := byRule[RuleSocket]; len(got) != 1 || got[0].Severity != "CRITICAL" || !strings.Contains(got[0].Title, "/var/run/docker.sock") {
		t.Errorf("sockets: %+v", got)
	}
	if got := byRule[RuleSetuidShell]; len(got) != 1 || got[0].Evidence != "/usr/bin/find" {
		t.Errorf("setuid: %+v", got)
	}
	if got := byRule[RuleCapability]; len(got) != 2 || got[0].Severity != "HIGH" || got[1].Severity != "MEDIUM" {
		t.Errorf("capabilities: %+v", got)
	}

	writable := map[string]Finding{}
	for _, finding := range byRule[RuleWritableByRoot] {
		writable[finding.Title] = finding
	}
	for title, severity := range map[string]string{
		"Its owner deploy can change /home/deploy/backup.sh, which root runs": "HIGH",
		"Every account can change /opt/jobs/cleanup.sh, which root runs":      "CRITICAL",
		"Group ops can change /opt/agent/run, which root runs":                "HIGH",
	} {
		if finding, ok := writable[title]; !ok || finding.Severity != severity {
			t.Errorf("missing %q (%s) in %v", title, severity, writable)
		}
	}
	if len(writable) != 3 {
		t.Errorf("writable: %v", writable)
	}
	if got := writable["Every account can change /opt/jobs/cleanup.sh, which root runs"]; !strings.Contains(got.Detail, "its directory /opt/jobs") {
		t.Errorf("directory: %s", got.Detail)
	}
	if got := byRule[RuleRootPath]; len(got) != 1 || got[0].Title != "Group staff can write to /usr/local/sbin, in root's PATH" {
		t.Errorf("root path: %+v", got)
	}

	secrets := map[string]string{}
	for _, rule := range []string{RulePrivateKey, RuleCredentials, RuleEnvFile} {
		for _, finding := range byRule[rule] {
			secrets[finding.Title] = finding.Severity
		}
	}
	for title, severity := range map[string]string{
		"Every account can read /home/deploy/.ssh/id_rsa, a private SSH key":                                         "HIGH",
		"Group staff can read /home/deploy/.git-credentials, saved passwords":                                        "HIGH",
		"Every account can read /var/www/shop/.env, application settings, which usually hold passwords and API keys": "HIGH",
		"Every account can read /etc/ssh/ssh_host_rsa_key, the machine's private SSH host key":                       "HIGH",
	} {
		if secrets[title] != severity {
			t.Errorf("missing %q (%s) in %v", title, severity, secrets)
		}
	}
	// Owner-only keys, public keys, the owner's own group and examples aren't exposed.
	if len(secrets) != 4 {
		t.Errorf("secrets: %v", secrets)
	}
	if !strings.HasPrefix(result.Summary, "12 ways to root, 4 secrets") {
		t.Errorf("summary: %s", result.Summary)
	}
	if len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "aliases") {
		t.Errorf("notes: %v", result.Notes)
	}
	for _, finding := range result.Findings {
		if len(finding.Path) < 3 {
			t.Errorf("no path: %+v", finding)
		}
	}
}

func TestAttackPathsWithoutSudo(t *testing.T) {
	result := analysePaths(map[string]string{"capabilities": noGetcap + "\n", "sudoers": "/etc/sudoers.d/x:deploy ALL=(ALL) NOPASSWD: ALL"}, false).result()
	if result.Status != StatusPartial || len(result.Findings) != 0 || len(result.Notes) != 2 || result.Summary != "0 ways to root, 0 secrets readable by others" {
		t.Fatalf("result: %+v", result)
	}
}

func TestShellEscapes(t *testing.T) {
	for program, want := range map[string]bool{"python3.11": true, "perl5.36": true, "nodejs": true, "python3-config": false, "vim": true, "passwd": false, "nodex": false} {
		if got := shellEscapes[program] || isInterpreter(program); got != want {
			t.Errorf("%s: %v", program, got)
		}
	}
}
