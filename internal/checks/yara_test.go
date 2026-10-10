package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/platform"
)

var ubuntu = platform.Platform{Family: platform.Ubuntu}

func TestNormalizeAdvancedScanAddsClamAV(t *testing.T) {
	got, err := Normalize([]string{YARA, Packages})
	if err != nil || strings.Join(got, ",") != "packages,antivirus,yara" {
		t.Fatalf("Normalize() = %v, %v", got, err)
	}
}

func TestYARAFindsMatchesAndDropsItsOwnRules(t *testing.T) {
	scan := `rules-directory /tmp/tmp.abc
{"path":"/tmp/tmp.abc/rules.yar","rules":[{"identifier":"SELF_MATCH","meta":[["score",100]]}]}
{"path":"/var/www/html/shell.php","rules":[{"identifier":"WEBSHELL_PHP_Generic_Eval","meta":[["description","Generic PHP webshell"],["author","Arnim Rupp"],["reference","https://example.org/rule"],["score",75],["hash","a"],["hash","b"]]}]}
{"path":"/tmp/xmrig","rules":[{"identifier":"MINER_Xmrig","meta":[["description","XMRig miner"],["score",90]]},{"identifier":"Weak_Hint","meta":[["score",50]]}]}
not json
`
	host := &fakeHost{answers: map[string]fakeAnswer{
		yaraDetectCommand:  {"/usr/local/bin/yr\n", nil},
		yaraVersionCommand: {"yara-x-cli 1.21.0\n", nil},
		yaraScanCommand:    {scan, nil},
	}}
	executor := NewExecutor(host, false, nil)
	result := Run(YARA, executor, ubuntu, time.Now(), Inputs{YARA: YARAInput{Rules: []byte("rule x { condition: true }"), Version: "YARA Forge core 2026-10-04"}})
	if result.Status != StatusPartial || len(result.Findings) != 3 {
		t.Fatalf("result = %+v", result)
	}
	shell, miner, weak := result.Findings[0], result.Findings[1], result.Findings[2]
	if shell.Rule != "yara.WEBSHELL_PHP_Generic_Eval" || shell.Severity != "HIGH" || shell.Evidence != "/var/www/html/shell.php" ||
		shell.Title != "YARA: Generic PHP webshell" || !strings.Contains(shell.Detail, "Arnim Rupp") || !strings.Contains(shell.Detail, "https://example.org/rule") {
		t.Fatalf("webshell finding = %+v", shell)
	}
	if miner.Severity != "CRITICAL" || weak.Severity != "LOW" || weak.Title != "YARA: Weak_Hint" {
		t.Fatalf("miner = %+v, weak = %+v", miner, weak)
	}
	if !strings.Contains(strings.Join(result.Notes, " "), "YARA Forge core 2026-10-04") {
		t.Fatalf("notes = %v", result.Notes)
	}
	// The rules reach the scan on standard input, never in the command.
	for i, command := range host.commands {
		if command == yaraScanCommand && string(host.stdin[i]) != "rule x { condition: true }" {
			t.Fatalf("stdin = %q", host.stdin[i])
		}
	}
}

func TestYARAWithSudoPasswordSendsPasswordThenRules(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{
		"sudo -n true":     {"", errors.New("sudo: a password is required")},
		yaraDetectCommand:  {"/usr/local/bin/yr\n", nil},
		yaraVersionCommand: {"yara-x-cli 1.21.0\n", nil},
	}}
	executor := NewExecutor(host, true, func(error) ([]byte, error) { return []byte("secret"), nil })
	defer executor.Close()
	result := Run(YARA, executor, ubuntu, time.Now(), Inputs{YARA: YARAInput{Rules: []byte("RULES"), Version: "v"}})
	if result.Status != StatusCompleted || !result.Privileged {
		t.Fatalf("result = %+v", result)
	}
	last := len(host.commands) - 1
	if !strings.HasPrefix(host.commands[last], "sudo -S -p '' -- sh -c ") || string(host.stdin[last]) != "secret\nRULES" {
		t.Fatalf("command = %q, stdin = %q", host.commands[last], host.stdin[last])
	}
}

func TestYARAIsNeverCleanWithoutRulesOrEngine(t *testing.T) {
	result := Run(YARA, NewExecutor(&fakeHost{}, false, nil), ubuntu, time.Now(), Inputs{YARA: YARAInput{Unavailable: "GitHub unreachable"}})
	if result.Status != StatusSkipped || !strings.Contains(strings.Join(result.Notes, " "), "GitHub unreachable") {
		t.Fatalf("without rules: %+v", result)
	}
	host := &fakeHost{answers: map[string]fakeAnswer{yaraDetectCommand: {"", nil}}}
	result = Run(YARA, NewExecutor(host, false, nil), ubuntu, time.Now(), Inputs{YARA: YARAInput{Rules: []byte("r")}})
	if result.Status != StatusSkipped || !strings.Contains(result.Summary, "not installed") {
		t.Fatalf("without yr: %+v", result)
	}
}
