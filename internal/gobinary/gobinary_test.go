package gobinary

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// matches checks Read against the standard library's own reader.
func matches(t *testing.T, path string) Info {
	t.Helper()
	want, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatalf("debug/buildinfo: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// HalfReader returns short reads, so chunk edges fall everywhere.
	got, err := Read(iotest.HalfReader(file), 1<<30)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if got.GoVersion != want.GoVersion || got.Main.Path != want.Main.Path || len(got.Deps) != len(want.Deps) {
		t.Fatalf("%s: got %s %s %d deps, want %s %s %d deps", path, got.GoVersion, got.Main.Path, len(got.Deps), want.GoVersion, want.Main.Path, len(want.Deps))
	}
	return got
}

func TestReadsThisTestBinary(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// This binary imports debug/buildinfo, so its read-only data holds the
	// magic too, before the real block.
	info := matches(t, executable)
	if !strings.HasPrefix(info.GoVersion, "go1.") {
		t.Fatalf("version %q", info.GoVersion)
	}
}

func TestReadsOtherPlatforms(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	os.WriteFile(source, []byte("package main\n\nfunc main() { println(\"hi\") }\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/hello\n\ngo 1.21\n"), 0o644)
	for _, target := range []string{"linux/amd64", "linux/arm64", "darwin/arm64", "darwin/amd64"} {
		system, arch, _ := strings.Cut(target, "/")
		output := filepath.Join(dir, system+"-"+arch)
		build := exec.Command("go", "build", "-o", output, ".")
		build.Dir = dir
		build.Env = append(os.Environ(), "GOOS="+system, "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", target, err, out)
		}
		start := make([]byte, 4)
		file, _ := os.Open(output)
		file.Read(start)
		file.Close()
		if !Executable(start) {
			t.Errorf("%s isn't recognised as a program", target)
		}
		if info := matches(t, output); info.Main.Path != "example.com/hello" {
			t.Errorf("%s: main module %q", target, info.Main.Path)
		}
	}
}

func TestNotGo(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":               nil,
		"text":                []byte("hello"),
		"a magic in the text": append(append(make([]byte, 32), magic...), bytes.Repeat([]byte{0}, 100)...),
		"a magic with a bad version": append(append(make([]byte, 32), magic...),
			append([]byte{8, flagInline}, append(make([]byte, 16), append([]byte{5}, "hello"...)...)...)...),
	} {
		if _, err := Read(bytes.NewReader(data), 1<<20); !errors.Is(err, ErrNotGo) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStdlibVersion(t *testing.T) {
	for goVersion, want := range map[string]string{
		"go1.26.9": "1.26.9", "go1.20": "1.20.0", "go1.21rc2": "1.21.0-rc.2", "go1.22beta1": "1.22.0-beta.1",
		"go1.22.3 X:boringcrypto": "1.22.3", "go1.24.1-bigcorp": "1.24.1", "devel go1.27-abc": "", "": "", "go1.x": "",
	} {
		if got := StdlibVersion(goVersion); got != want {
			t.Errorf("%q: %q, want %q", goVersion, got, want)
		}
	}
}

func TestRecord(t *testing.T) {
	info := Info{GoVersion: "go1.26.9", Main: Module{"example.com/app", "(devel)"},
		Deps: []Module{{"golang.org/x/net", "v0.7.0"}, {"bad\tpath", "v1"}}}
	want := RecordMarker + "stdlib\t1.26.9\ngolang.org/x/net\tv0.7.0\n"
	if got := string(info.Record()); got != want {
		t.Fatalf("record %q", got)
	}
}
