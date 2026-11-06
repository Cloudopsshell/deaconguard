package live

import (
	"strings"
	"testing"
)

func TestPrivilegeRules(t *testing.T) {
	root := func(how int, ids ...uint32) Event {
		event := Event{Kind: KindPrivilege, PID: 40, UID: 1000, Comm: "exploit", How: how, IDs: [3]uint32{unchanged, unchanged, unchanged}}
		copy(event.IDs[:], ids)
		return event
	}
	cases := []struct {
		name    string
		event   Event
		machine fakeMachine
		want    string
	}{
		{"sudo, setuid root", root(CallSetRESUID, 0, 0, 0), fakeMachine{executable: "/usr/bin/sudo", privileged: true}, ""},
		{"a program that isn't setuid", root(CallSetUID, 0), fakeMachine{executable: "/home/a/exploit"}, "DG-RT-030 HIGH"},
		{"from /tmp", root(CallSetUID, 0), fakeMachine{executable: "/tmp/x"}, "DG-RT-030 CRITICAL"},
		{"marked by a /tmp parent", func() Event { e := root(CallSetUID, 0); e.Marked = true; return e }(), fakeMachine{executable: "/usr/bin/sudo", privileged: true}, "DG-RT-030 CRITICAL"},
		{"root inside a user namespace", root(CallSetUID, 0), fakeMachine{executable: "/usr/bin/unshare", effective: 1000}, ""},
		{"only the saved ID", root(CallSetRESUID, 1000, 1000, 0), fakeMachine{executable: "/usr/bin/thing", effective: 1000}, ""},
		{"failed", func() Event { e := root(CallSetUID, 0); e.Result = -1; return e }(), fakeMachine{executable: "/home/a/x"}, ""},
		{"ended, named like sudo", func() Event { e := root(CallSetUID, 0); e.Comm = "sudo"; return e }(), fakeMachine{effective: -1}, ""},
		{"ended, unknown name", root(CallSetUID, 0), fakeMachine{effective: -1}, "DG-RT-030 HIGH"},
	}
	for _, c := range cases {
		if got := rules(Evaluate(c.event, c.machine)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	alert := Evaluate(root(CallSetREUID, unchanged, 0), fakeMachine{executable: "/opt/x"})[0]
	if alert.Detail == "" || !contains(alert.Detail, "setreuid(-1, 0)") {
		t.Errorf("detail doesn't say the call: %s", alert.Detail)
	}
}

func TestModuleRules(t *testing.T) {
	load := func(comm string, how int) Event {
		return Event{Kind: KindModule, PID: 50, Comm: comm, How: how, Target: 3}
	}
	cases := []struct {
		name    string
		event   Event
		machine fakeMachine
		want    string
	}{
		{"modprobe, system module", load("modprobe", CallFileModule), fakeMachine{file: "/usr/lib/modules/6.8.0/kernel/fs/xfs.ko.zst"}, ""},
		{"udev worker, from memory", load("(udev-worker)", CallMemModule), fakeMachine{}, ""},
		{"insmod from /tmp", load("insmod", CallFileModule), fakeMachine{file: "/tmp/rk.ko"}, "DG-RT-031 CRITICAL"},
		{"insmod from /root", load("insmod", CallFileModule), fakeMachine{file: "/root/rk.ko"}, "DG-RT-031 HIGH"},
		{"insmod, closed, path on its command line", load("insmod", CallMemModule), fakeMachine{cmdline: []string{"insmod", "rk.ko"}, directory: "/opt/x"}, "DG-RT-031 HIGH"},
		{"own loader, from memory", load("kworkerd", CallMemModule), fakeMachine{executable: "/usr/local/bin/kworkerd"}, "DG-RT-031 HIGH"},
		{"own loader, system module", load("vboxdrv.sh", CallFileModule), fakeMachine{file: "/lib/modules/6.8.0/misc/vboxdrv.ko"}, "DG-RT-031 MEDIUM"},
		{"already loaded", func() Event { e := load("insmod", CallFileModule); e.Result = -errExists; return e }(), fakeMachine{file: "/root/rk.ko"}, ""},
		{"refused", func() Event { e := load("insmod", CallFileModule); e.Result = -1; return e }(), fakeMachine{file: "/tmp/rk.ko"}, "DG-RT-031 CRITICAL"},
	}
	for _, c := range cases {
		if got := rules(Evaluate(c.event, c.machine)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	alert := Evaluate(load("insmod", CallFileModule), fakeMachine{file: "/root/rk.ko"})[0]
	if alert.Path != "/root/rk.ko" || !contains(alert.Title, "rk from /root") {
		t.Errorf("alert: %+v", alert)
	}
	refused := Evaluate(func() Event { e := load("insmod", CallFileModule); e.Result = -8; return e }(), fakeMachine{file: "/root/rk.ko"})[0]
	if !contains(refused.Title, "tried to load") || !contains(refused.Detail, "not a valid module") {
		t.Errorf("refused: %+v", refused)
	}
}

func TestTraceRules(t *testing.T) {
	attach := func(comm string) Event {
		return Event{Kind: KindTrace, PID: 60, Comm: comm, How: CallAttach, Target: 812}
	}
	write := func(comm string) Event {
		return Event{Kind: KindTrace, PID: 60, Comm: comm, How: CallVMWrite, Target: 812, Result: 64}
	}
	sshd := map[uint32]string{812: "sshd"}
	cases := []struct {
		name    string
		event   Event
		machine fakeMachine
		want    string
	}{
		{"gdb at a terminal", attach("gdb"), fakeMachine{executable: "/usr/bin/gdb", terminal: true, names: map[uint32]string{812: "myapp"}}, ""},
		{"gdb from a script", attach("gdb"), fakeMachine{executable: "/usr/bin/gdb", names: map[uint32]string{812: "myapp"}}, "DG-RT-032 MEDIUM"},
		{"strace on sshd", attach("strace"), fakeMachine{executable: "/usr/bin/strace", terminal: true, names: sshd}, "DG-RT-032 HIGH"},
		{"unknown tracer", attach("helper"), fakeMachine{executable: "/usr/local/bin/helper", names: map[uint32]string{812: "nginx"}}, "DG-RT-032 HIGH"},
		{"tracer from /dev/shm", attach("x"), fakeMachine{executable: "/dev/shm/x", names: sshd}, "DG-RT-032 CRITICAL"},
		{"refused", func() Event { e := attach("helper"); e.Result = -1; return e }(), fakeMachine{executable: "/usr/local/bin/helper"}, ""},
		{"target gone", attach("helper"), fakeMachine{executable: "/usr/local/bin/helper", hostPID: map[uint32]uint32{812: 0}}, ""},
		{"memory write", write("inject"), fakeMachine{executable: "/usr/local/bin/inject", names: map[uint32]string{812: "nginx"}}, "DG-RT-033 HIGH"},
		{"memory write by a debugger", write("gdb"), fakeMachine{executable: "/usr/bin/gdb", terminal: true, names: map[uint32]string{812: "myapp"}}, "DG-RT-033 MEDIUM"},
		{"memory write into itself", func() Event { e := write("app"); e.Target = 60; return e }(), fakeMachine{executable: "/usr/bin/app"}, ""},
		{"nothing written", func() Event { e := write("inject"); e.Result = 0; return e }(), fakeMachine{executable: "/usr/local/bin/inject"}, ""},
	}
	for _, c := range cases {
		if got := rules(Evaluate(c.event, c.machine)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// A process in a container names its target by the container's ID.
	alert := Evaluate(attach("helper"), fakeMachine{executable: "/usr/local/bin/helper", hostPID: map[uint32]uint32{812: 4242},
		names: map[uint32]string{4242: "sshd"}, executables: map[uint32]string{4242: "/usr/sbin/sshd", 60: "/usr/local/bin/helper"}})[0]
	if alert.Path != "/usr/sbin/sshd (process 4242)" || !contains(alert.Title, "took control of sshd") {
		t.Errorf("alert: %+v", alert)
	}
}

func TestParseCallEvent(t *testing.T) {
	raw := make([]byte, eventSize)
	raw[0] = KindModule
	raw[4] = 7
	raw[32] = CallFileModule
	raw[36] = 3
	copy(raw[40:], "insmod")
	for i := 72; i < 80; i++ {
		raw[i] = 0xff // -1
	}
	raw[92] = 1
	copy(raw[328:], "debug=1")
	event, err := ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != KindModule || event.PID != 7 || event.How != CallFileModule || event.Target != 3 || event.Comm != "insmod" ||
		event.Result != -1 || !event.Marked || event.Args != "debug=1" {
		t.Errorf("%+v", event)
	}
}

func contains(text, part string) bool { return strings.Contains(text, part) }
