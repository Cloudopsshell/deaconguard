package checks

import (
	"strings"
	"testing"
	"time"

	"deaconguard/internal/containers"
)

var running = []containers.Writable{
	{ID: "a", Name: "shop/web-7d9/php", Dirs: []containers.WritableDir{
		{HostPath: "/var/lib/docker/overlay2/a1/diff", Path: "/"},
		{HostPath: "/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/tmp", Path: "/tmp"},
	}},
	{ID: "b", Name: "redis"},
}

func TestContainerFoldersAndTemporaryFolders(t *testing.T) {
	folders, count := containerFolders(running)
	if count != 1 || folders != "/var/lib/docker/overlay2/a1/diff\n/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/tmp\n" {
		t.Fatalf("containerFolders() = %q, %d", folders, count)
	}
	temp := containerTempFolders(running)
	want := "/var/lib/docker/overlay2/a1/diff/tmp\n/var/lib/docker/overlay2/a1/diff/var/tmp\n/var/lib/docker/overlay2/a1/diff/dev/shm\n" +
		"/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/tmp\n"
	if temp != want {
		t.Fatalf("containerTempFolders() = %q", temp)
	}
}

func TestPathsMapIntoTheirContainer(t *testing.T) {
	for hostPath, want := range map[string]string{
		"/var/lib/docker/overlay2/a1/diff/var/www/shell.php":                    "/var/www/shell.php",
		"/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/tmp/.x/miner": "/tmp/.x/miner",
	} {
		name, inside, found := inContainer(hostPath, running)
		if !found || name != "shop/web-7d9/php" || inside != want {
			t.Errorf("inContainer(%q) = %q, %q, %v", hostPath, name, inside, found)
		}
	}
	// A sibling folder whose name starts the same isn't inside.
	if _, _, found := inContainer("/var/lib/docker/overlay2/a1/diff2/x", running); found {
		t.Fatal("matched a sibling folder")
	}
}

func TestClamAVScansContainersInOneRun(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{
		clamDetectCommand:  {"/usr/bin/clamscan\n", nil},
		clamVersionCommand: {"ClamAV 1.4.1/27800/" + time.Now().UTC().Format("Mon Jan _2 15:04:05 2006") + "\n", nil},
		memInfoCommand:     {"MemAvailable: 4000000 kB\nSwapFree: 0 kB\n", nil},
		clamScanCommand: {"/var/lib/docker/overlay2/a1/diff/var/www/up.php: Php.Webshell-1 FOUND\n" +
			"/home/bob/eicar.com: Eicar-Test-Signature FOUND\n", nil},
	}}
	executor := NewExecutor(host, false, nil)
	executor.AsRoot()
	result := Run(Antivirus, executor, ubuntu, time.Now(), Inputs{Containers: running, ContainersSkipped: 2})
	if len(result.Findings) != 2 {
		t.Fatalf("result = %+v", result)
	}
	inside, own := result.Findings[0], result.Findings[1]
	if inside.Container != "shop/web-7d9/php" || inside.Evidence != "/var/www/up.php" ||
		inside.Title != "shop/web-7d9/php: ClamAV detected Php.Webshell-1" || !strings.HasPrefix(inside.Detail, "ClamAV matched this file") || !strings.Contains(inside.Detail, "Isolate the container") || strings.Contains(inside.Detail, "host") {
		t.Fatalf("container finding = %+v", inside)
	}
	if own.Container != "" || own.Evidence != "/home/bob/eicar.com" {
		t.Fatalf("host finding = %+v", own)
	}
	notes := strings.Join(result.Notes, " ")
	if !strings.Contains(notes, "what 1 running container wrote since starting (2 folders") || !strings.Contains(notes, "of 2 running containers could not be found") {
		t.Fatalf("notes = %v", result.Notes)
	}
	scans := 0
	for i, command := range host.commands {
		if command == clamScanCommand {
			scans++
			if string(host.stdin[i]) != "/var/lib/docker/overlay2/a1/diff\n/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/tmp\n" {
				t.Fatalf("stdin = %q", host.stdin[i])
			}
		}
	}
	if scans != 1 {
		t.Fatalf("clamscan ran %d times", scans)
	}
}

func TestYARAFindsMatchesInContainers(t *testing.T) {
	host := &fakeHost{answers: map[string]fakeAnswer{
		yaraDetectCommand:  {"/usr/local/bin/yr\n", nil},
		yaraVersionCommand: {"yara-x-cli 1.21.0\n", nil},
		yaraScanCommand: {"rules-directory /tmp/tmp.q\n" +
			`{"path":"/var/lib/kubelet/pods/p1/volumes/kubernetes.io~empty-dir/tmp/kinsing","rules":[{"identifier":"MAL_Kinsing","meta":[["score",90]]}]}` + "\n", nil},
	}}
	executor := NewExecutor(host, false, nil)
	executor.AsRoot()
	result := Run(YARA, executor, ubuntu, time.Now(), Inputs{YARA: YARAInput{Rules: []byte("R"), Version: "v"}, Containers: running})
	if len(result.Findings) != 1 || result.Findings[0].Container != "shop/web-7d9/php" || result.Findings[0].Evidence != "/tmp/kinsing" {
		t.Fatalf("result = %+v", result)
	}
	for i, command := range host.commands {
		if command == yaraScanCommand && !strings.HasPrefix(string(host.stdin[i]), "/var/lib/docker/overlay2/a1/diff\n") {
			t.Fatalf("stdin = %q", host.stdin[i])
		}
	}
}

func TestTemporaryExecutablesInContainers(t *testing.T) {
	var result Result
	checkTemporaryExecutables(&result, []byte(
		"/var/lib/docker/overlay2/a1/diff/tmp/.cache/kdevtmpfsi\t2400000\troot\n"+
			"/somewhere/else/tmp/x\t10\troot\n"), running)
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Rule != "malware.hidden-temp-executable" || finding.Container != "shop/web-7d9/php" ||
		finding.Evidence != "/tmp/.cache/kdevtmpfsi (2400000 bytes, owner root)" {
		t.Fatalf("finding = %+v", finding)
	}
}
