package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerOf(t *testing.T) {
	id := strings.Repeat("ab12", 16)
	for name, test := range map[string]struct{ cgroup, want string }{
		"host service":           {"0::/system.slice/ssh.service\n", ""},
		"host session":           {"0::/user.slice/user-1000.slice/session-3.scope\n", ""},
		"docker, systemd":        {"0::/system.slice/docker-" + id + ".scope\n", id},
		"docker, cgroupfs":       {"0::/docker/" + id + "\n", id},
		"podman":                 {"0::/machine.slice/libpod-" + id + ".scope/container\n", id},
		"containerd in a pod":    {"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b_3c4d.slice/cri-containerd-" + id + ".scope\n", id},
		"k3s, cgroupfs":          {"0::/kubepods/besteffort/pod1a2b-3c4d/" + id + "\n", id},
		"cri-o":                  {"0::/kubepods.slice/kubepods-pod1.slice/crio-" + id + ".scope\n", id},
		"cgroup v1":              {"12:pids:/docker/" + id + "\n11:memory:/docker/" + id + "\n0::/\n", id},
		"a service in one":       {"0::/system.slice/docker-" + id + ".scope/system.slice/cron.service\n", id},
		"not hex":                {"0::/docker/" + strings.Repeat("zz", 32) + "\n", ""},
		"too short":              {"0::/docker/abc123\n", ""},
		"nothing":                {"", ""},
		"a pod slice is not one": {"0::/kubepods.slice/kubepods-besteffort.slice\n", ""},
	} {
		if got := containerOf(test.cgroup); got != test.want {
			t.Errorf("%s: %q, want %q", name, got, test.want)
		}
	}
}

func TestContainerNames(t *testing.T) {
	id := strings.Repeat("0f", 32)
	asked := 0
	var names containerNames
	names.setLookup(func(got string) (Container, bool, error) {
		asked++
		if got != id {
			return Container{}, false, nil
		}
		return Container{Name: "api", Image: "ghcr.io/acme/api:2.1", Namespace: "shop", Pod: "api-7d9f"}, true, nil
	})
	now := time.Now()
	alerts := []Alert{{Rule: RuleMiner, ContainerID: id}, {Rule: RuleMiner, ContainerID: id}, {Rule: RuleMiner}, {Rule: RuleMiner, ContainerID: strings.Repeat("1", 64)}}
	names.describe(alerts, now)
	if alerts[0].Container != "api" || alerts[1].Pod != "api-7d9f" || alerts[2].Container != "" || alerts[3].Container != "" {
		t.Fatalf("described: %+v", alerts)
	}
	if asked != 2 {
		t.Fatalf("asked the runtime %d times, want once per container", asked)
	}
	// Unknown containers are asked about again only after a while.
	names.describe([]Alert{{ContainerID: strings.Repeat("1", 64)}}, now.Add(time.Minute))
	names.describe([]Alert{{ContainerID: strings.Repeat("1", 64)}}, now.Add(containerUnknown+time.Second))
	if asked != 3 {
		t.Fatalf("asked %d times", asked)
	}
	cached := Alert{ContainerID: id}
	names.cached(&cached, now)
	if cached.Image != "ghcr.io/acme/api:2.1" {
		t.Fatalf("cached: %+v", cached)
	}
}

func TestAllow(t *testing.T) {
	alert := Alert{Rule: RuleTempProgram, Program: "/tmp/build/run", Path: "", Container: "builder", Image: "registry.local:5000/ci/builder:1.4", Namespace: "ci"}
	for name, test := range map[string]struct {
		rule Allow
		want bool
	}{
		"program":               {Allow{Rule: RuleTempProgram, Program: "/tmp/build/run"}, true},
		"other rule":            {Allow{Rule: RuleMiner, Program: "/tmp/build/run"}, false},
		"other program":         {Allow{Rule: RuleTempProgram, Program: "/tmp/other"}, false},
		"image, every tag":      {Allow{Rule: RuleTempProgram, Image: "registry.local:5000/ci/builder"}, true},
		"image, this tag":       {Allow{Rule: RuleTempProgram, Image: "registry.local:5000/ci/builder:1.4"}, true},
		"image, another tag":    {Allow{Rule: RuleTempProgram, Image: "registry.local:5000/ci/builder:1.5"}, false},
		"image, registry only":  {Allow{Rule: RuleTempProgram, Image: "registry.local:5000"}, false},
		"namespace and program": {Allow{Rule: RuleTempProgram, Namespace: "ci", Program: "/tmp/build/run"}, true},
		"other namespace":       {Allow{Rule: RuleTempProgram, Namespace: "prod", Program: "/tmp/build/run"}, false},
		"container":             {Allow{Rule: RuleTempProgram, Container: "builder"}, true},
		"path must match too":   {Allow{Rule: RuleTempProgram, Program: "/tmp/build/run", Path: "/etc/x"}, false},
		"no rule matches none":  {Allow{Program: "/tmp/build/run"}, false},
	} {
		if got := test.rule.Matches(alert); got != test.want {
			t.Errorf("%s: %v, want %v", name, got, test.want)
		}
	}
	if (Allow{Rule: RuleTempProgram, Program: "/tmp/x"}).Matches(Alert{Rule: RuleTempProgram, Program: "/tmp/x", Test: true}) {
		t.Error("a test alert was skipped")
	}
	if (Allow{Rule: RuleTempProgram, Image: "nginx"}).Matches(Alert{Rule: RuleTempProgram}) {
		t.Error("an image rule matched an alert from outside containers")
	}
	if !(Allow{Rule: RuleTempProgram, Image: "nginx"}).Matches(Alert{Rule: RuleTempProgram, Image: "nginx@sha256:abc"}) {
		t.Error("an image rule without tag didn't match a digest")
	}
}

func TestDetectorAllowlist(t *testing.T) {
	d := NewDetector("", t.Logf)
	id := strings.Repeat("c3", 32)
	d.SetContainerLookup(func(string) (Container, bool, error) {
		return Container{Name: "backup", Image: "acme/backup:3"}, true, nil
	})
	d.SetAllowlist([]Allow{{ID: 7, Rule: RuleModule, Program: "/usr/sbin/insmod"}, {ID: 9, Rule: RuleTempProgram, Image: "acme/backup"}})
	now := time.Now()
	var noisy []Alert
	for range 40 {
		noisy = append(noisy, Alert{Rule: RuleModule, Program: "/usr/sbin/insmod", Path: "/opt/zfs.ko"})
	}
	// Expected alerts don't count against the rate limit.
	d.add(append(noisy, Alert{Rule: RuleMiner, Program: "/tmp/xmrig"}), now)
	// One from a container is skipped once its name is known.
	d.add([]Alert{{Rule: RuleTempProgram, Program: "/tmp/dump", ContainerID: id}}, now)
	status, alerts := d.Take()
	if len(alerts) != 1 || alerts[0].Rule != RuleMiner || status.Allowed[7] != 40 || status.Allowed[9] != 1 || status.Suppressed != 0 {
		t.Fatalf("alerts %+v, allowed %v, suppressed %d", alerts, status.Allowed, status.Suppressed)
	}
	// Counts that couldn't be sent go with the next report.
	d.Unsent(status)
	if status, _ := d.Take(); status.Allowed[7] != 40 {
		t.Fatalf("after unsent: %v", status.Allowed)
	}
	if status, _ := d.Take(); status.Allowed != nil {
		t.Fatalf("counted twice: %v", status.Allowed)
	}
	// Now known, the container's next alert is skipped before the limits.
	d.add([]Alert{{Rule: RuleTempProgram, Program: "/tmp/other", ContainerID: id}}, now.Add(time.Second))
	d.mu.Lock()
	pending := len(d.pending)
	d.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d pending", pending)
	}
}

func TestCgroupIndex(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("7d", 32)
	inodes := map[string]uint64{}
	next := uint64(100)
	mkdir := func(path string) uint64 {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
		next++
		inodes[filepath.Join(root, path)] = next
		return next
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	service := mkdir("system.slice/ssh.service")
	pod := mkdir("kubepods/besteffort/pod1a2b")
	container := mkdir("kubepods/besteffort/pod1a2b/" + id)
	inside := mkdir("kubepods/besteffort/pod1a2b/" + id + "/init.scope")
	walks := 0
	index := &cgroupIndex{roots: []string{filepath.Join(root, "missing"), root}, inode: func(path string) uint64 {
		walks++
		return inodes[path]
	}}
	now := time.Now()
	for name, test := range map[string]struct {
		id    uint64
		want  string
		known bool
	}{
		"a container":           {container, id, true},
		"a cgroup inside one":   {inside, id, true},
		"a service":             {service, "", false},
		"a pod's own cgroup":    {pod, "", false},
		"an ID the walk missed": {9999, "", false},
		"no ID":                 {0, "", false},
	} {
		if got, known := index.container(test.id, now); got != test.want || known != test.known {
			t.Errorf("%s: %q %v, want %q %v", name, got, known, test.want, test.known)
		}
	}
	// One walk, until an unknown ID asks again after a while.
	before := walks
	index.container(9999, now.Add(time.Second))
	if walks != before {
		t.Fatal("walked again at once")
	}
	added := mkdir("system.slice/docker-" + strings.Repeat("e1", 32) + ".scope")
	if got, _ := index.container(added, now.Add(cgroupRebuild+time.Second)); got != strings.Repeat("e1", 32) {
		t.Fatalf("a new container: %q", got)
	}
	// Without a cgroup v2 tree, it can't tell.
	none := &cgroupIndex{roots: []string{filepath.Join(root, "missing")}, inode: func(string) uint64 { return 1 }}
	if _, known := none.container(5, now); known {
		t.Fatal("known without a tree")
	}
}

func TestInContainers(t *testing.T) {
	id := strings.Repeat("ab", 32)
	machine := fakeMachine{cgroup: "0::/docker/" + id + "\n"}
	alerts := []Alert{{Rule: RuleMiner, PID: 5}, {Rule: RuleTempProgram, PID: 5, Test: true}}
	// No tree: from /proc.
	inContainers(Event{PID: 5, Cgroup: 77}, alerts, machine, &cgroupIndex{}, time.Now())
	if alerts[0].ContainerID != id || alerts[1].ContainerID != "" {
		t.Fatalf("from /proc: %+v", alerts)
	}
	// The tree's answer wins over /proc's, which may be another process with
	// that number by now.
	other := strings.Repeat("cd", 32)
	known := &cgroupIndex{inode: func(string) uint64 { return 0 }, byID: map[uint64]string{77: other}, builtAt: time.Now()}
	alerts = []Alert{{Rule: RuleMiner, PID: 5}}
	inContainers(Event{PID: 5, Cgroup: 77}, alerts, machine, known, time.Now())
	if alerts[0].ContainerID != other {
		t.Fatalf("by cgroup ID: %+v", alerts)
	}
}
