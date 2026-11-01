package checks

import (
	"strings"
	"testing"
)

func TestReadSnapshot(t *testing.T) {
	facts := map[string]string{
		SectionListening: strings.Join([]string{
			`tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))`,
			`tcp   LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=812,fd=4))`,
			`tcp   LISTEN 0      4096       127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=900,fd=5))`,
			`udp   UNCONN 0      0            0.0.0.0:41234      0.0.0.0:*    users:(("chronyd",pid=700,fd=6))`,
		}, "\n"),
		SectionUsers:    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash",
		SectionAdmins:   "sudo:x:27:deploy,ops",
		SectionServices: "ssh.service enabled enabled\ncron.service enabled enabled",
		SectionSudoers:  "/etc/sudoers.d/deploy:deploy ALL=(ALL) NOPASSWD: ALL",
		SectionKeys: "root 0 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@laptop\n" +
			`deploy 1000 no-pty,command="echo hi there" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl` + "\n" +
			"deploy 1000 # a comment\nroot 0 ssh-rsa not-base64!\ntoor 0 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		SectionCron: "/etc/crontab:SHELL=/bin/sh\n/etc/cron.d/backup:0 3 * * * root curl -u admin:hunter2 https://backup.example.com/run?token=s3cr3t\n/etc/cron.d/db:0 4 * * * root mysqldump -pTopSecret --all-databases",
	}
	snapshot := ReadSnapshot(facts, true)
	keys := func(section string) string {
		var list []string
		for _, item := range snapshot.Sections[section] {
			list = append(list, item.Key)
		}
		return strings.Join(list, "|")
	}
	// One entry per port and address kind; the ephemeral UDP port is left out.
	if got := keys(SectionListening); got != "tcp *:22|tcp localhost:5432" {
		t.Fatalf("listening: %s", got)
	}
	if item := snapshot.Sections[SectionListening][0]; !item.Exposed || item.Text != "TCP port 22, open to the network (sshd)" {
		t.Fatalf("ssh: %+v", item)
	}
	if got := keys(SectionUsers); got != "deploy uid 1000|root uid 0" {
		t.Fatalf("users: %s", got)
	}
	if got := keys(SectionAdmins); got != "deploy in sudo|ops in sudo" {
		t.Fatalf("admins: %s", got)
	}
	if got := keys(SectionServices); got != "cron.service|ssh.service" {
		t.Fatalf("services: %s", got)
	}
	if got := keys(SectionKeys); got != "deploy SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU|root SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU|toor SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU" {
		t.Fatalf("keys: %s", got)
	}
	if text := snapshot.Sections[SectionKeys][1].Text; text != "ED25519 key for root, SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU (ops@laptop)" {
		t.Fatalf("key text: %s", text)
	}
	if keys := snapshot.Sections[SectionKeys]; keys[0].Root || !keys[1].Root || !keys[2].Root || keys[2].Text != "ED25519 key for toor (UID 0), SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU" {
		t.Fatalf("root keys: %+v", keys)
	}
	// Environment lines are left out; a secret never reaches the text or the key.
	cron := snapshot.Sections[SectionCron]
	if len(cron) != 2 || strings.Contains(cron[0].Text, "hunter2") || strings.Contains(cron[1].Text, "TopSecret") || strings.Contains(cron[0].Text, "s3cr3t") ||
		strings.Contains(cron[0].Key, "hunter2") || !strings.HasPrefix(cron[0].Key, "/etc/cron.d/backup ") {
		t.Fatalf("cron: %+v", cron)
	}
	if len(snapshot.Sections[SectionSudoers]) != 1 {
		t.Fatalf("sudoers: %+v", snapshot.Sections[SectionSudoers])
	}

	// Without root, the root sections are absent, not empty.
	plain := ReadSnapshot(facts, false)
	if _, ok := plain.Sections[SectionKeys]; ok {
		t.Fatalf("keys without root: %+v", plain.Sections)
	}
}
