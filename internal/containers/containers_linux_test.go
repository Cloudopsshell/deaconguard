//go:build linux

package containers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, path, contents string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A container can't make the agent read a file outside it: links are never
// followed, in the file itself or in any folder on the way.
func TestSymlinksAreNeverFollowed(t *testing.T) {
	host := t.TempDir()
	write(t, host, "secret", "host secret")
	container := t.TempDir()
	write(t, container, "etc/hostname", "box")
	os.MkdirAll(filepath.Join(container, "var/lib/dpkg"), 0o755)
	os.Symlink(filepath.Join(host, "secret"), filepath.Join(container, "var/lib/dpkg/status"))
	os.Symlink(host, filepath.Join(container, "escape"))
	os.Symlink("../escape", filepath.Join(container, "etc/up"))
	r, err := openRoot(container)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	for _, path := range []string{"/var/lib/dpkg/status", "/escape/secret", "/etc/up/secret"} {
		data, _, err := r.readFile(path, 1024)
		if err == nil || strings.Contains(string(data), "host secret") {
			t.Errorf("%s: read %q, %v; want refused", path, data, err)
		}
		if !errors.Is(err, ErrSymlink) {
			t.Errorf("%s: err = %v, want ErrSymlink", path, err)
		}
	}
	if _, _, err := r.readFile("/etc/../../secret", 1024); err == nil {
		t.Error(`".." must be refused`)
	}
	if data, _, err := r.readFile("/etc/hostname", 1024); err != nil || string(data) != "box" {
		t.Errorf("a plain file: %q, %v", data, err)
	}
}

func TestReadContainer(t *testing.T) {
	container := t.TempDir()
	// os-release is usually a link to ../usr/lib/os-release; the real file is read instead.
	write(t, container, "usr/lib/os-release", "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n")
	os.Symlink("../usr/lib/os-release", filepath.Join(container, "etc/os-release"))
	// distroless: one file per package, without Status.
	write(t, container, "var/lib/dpkg/status.d/libc6", "Package: libc6\nVersion: 2.36-9+deb12u4\nArchitecture: amd64\nSource: glibc\n")
	write(t, container, "var/lib/dpkg/status.d/libc6.md5sums", "ignored")
	write(t, container, "app/package-lock.json", `{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`)
	write(t, container, "app/node_modules/lodash/package.json", `{"name":"lodash","version":"4.17.20"}`)
	write(t, container, "usr/local/lib/node_modules/npm/package.json", `{"name":"npm","version":"10.2.0"}`)
	write(t, container, "usr/local/lib/python3.12/site-packages/requests-2.25.1.dist-info/METADATA", "Name: requests\nVersion: 2.25.1\n")
	write(t, container, "usr/lib/python3/dist-packages/six-1.16.0.dist-info/METADATA", "Name: six\nVersion: 1.16.0\n")
	r, err := openRoot(container)
	if err != nil {
		t.Fatal(err)
	}
	result := Inventory{}
	result.OSRelease = readFirst(r, &result, 16<<10, "/etc/os-release", "/usr/lib/os-release")
	result.DPKGStatus = readDPKG(r, &result)
	found := walkLibraries(r)
	r.close()
	if !strings.Contains(result.OSRelease, "ID=debian") {
		t.Errorf("os-release = %q", result.OSRelease)
	}
	if !strings.Contains(result.DPKGStatus, "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\nSource: glibc") {
		t.Errorf("dpkg = %q", result.DPKGStatus)
	}
	got := map[string]bool{}
	for _, l := range found.Libraries {
		got[l.Name+" "+l.Version+" "+strings.Join(l.Paths, ",")] = true
	}
	for _, want := range []string{
		"lodash 4.17.20 /app/package-lock.json",
		"npm 10.2.0 /usr/local/lib/node_modules/npm/package.json",
		"requests 2.25.1 /usr/local/lib/python3.12/site-packages/requests-2.25.1.dist-info/METADATA",
	} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("libraries = %v: /usr/lib is the distribution's, and a project's node_modules is listed by its lock file", got)
	}
}
