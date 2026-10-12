package local

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostPath(t *testing.T) {
	for _, test := range []struct{ root, want string }{
		{"", "/etc/os-release"},
		{"/", "/etc/os-release"},
		{"/host", "/host/etc/os-release"},
		{"/host/", "/host/etc/os-release"},
	} {
		t.Setenv("DEACONGUARD_HOST_ROOT", test.root)
		if got := HostPath("/etc/os-release"); got != test.want {
			t.Errorf("root %q: %s, want %s", test.root, got, test.want)
		}
	}
}

func TestHostnameInAContainer(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hostname"), []byte("node-7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEACONGUARD_HOST_ROOT", root)
	t.Setenv("DEACONGUARD_HOSTNAME", "")
	if got := Hostname(); got != "node-7" {
		t.Fatalf("from the host's /etc/hostname: %q", got)
	}
	t.Setenv("DEACONGUARD_HOSTNAME", "worker-3")
	if got := Hostname(); got != "worker-3" {
		t.Fatalf("from DEACONGUARD_HOSTNAME: %q", got)
	}
}

func TestHostPathResolvesLinksInsideTheRoot(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"usr/bin", "usr/lib", "etc"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ target, name string }{
		{"usr/bin", "bin"},          // relative, as with merged /usr
		{"/bin/bash", "usr/bin/sh"}, // absolute: must stay in the root
		{"../usr/lib/os-release", "etc/os-release"},
		{"/etc/loop", "etc/loop"},
	} {
		if err := os.Symlink(link.target, filepath.Join(root, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/bash"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEACONGUARD_HOST_ROOT", root)
	for path, want := range map[string]string{
		"/bin/sh":           "/usr/bin/bash",
		"/etc/os-release":   "/usr/lib/os-release",
		"/etc/hostname":     "/etc/hostname",
		"/../../etc/shadow": "/etc/shadow",
	} {
		if got := HostPath(path); got != filepath.Join(root, want) {
			t.Errorf("%s: %s, want %s", path, got, filepath.Join(root, want))
		}
	}
	if got := HostPath("/etc/loop"); !strings.HasPrefix(got, root) {
		t.Errorf("a loop left the root: %s", got)
	}
}
