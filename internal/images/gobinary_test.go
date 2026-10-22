package images

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"testing"

	"deaconguard/internal/containers"
)

func programTar(t *testing.T, files map[string][]byte, modes map[string]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for name, data := range files {
		mode := int64(0o644)
		if m, ok := modes[name]; ok {
			mode = m
		}
		w.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg})
		w.Write(data)
	}
	w.Close()
	return buf.Bytes()
}

func TestGoProgramsInImageLayers(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	// Layer 1: two programs. Layer 2 deletes one, as a whiteout.
	first, err := readLayer(context.Background(), bytes.NewReader(programTar(t, map[string][]byte{
		"usr/local/bin/app": program, "opt/tool": program, "etc/data": []byte("not a program"),
	}, map[string]int64{"usr/local/bin/app": 0o755, "opt/tool": 0o755})), "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := readLayer(context.Background(), bytes.NewReader(programTar(t, map[string][]byte{"opt/.wh.tool": nil}, nil)), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Files["/usr/local/bin/app"]) > 64<<10 {
		t.Fatalf("the layer kept the whole program (%d bytes), not its record", len(first.Files["/usr/local/bin/app"]))
	}
	fs := newFileSystem()
	fs.apply(first)
	fs.apply(second)
	inventory := containers.ReadFS(fs, containers.Container{Name: "test"})
	var stdlib []string
	for _, library := range inventory.Libraries.Libraries {
		if library.Name == "stdlib" {
			stdlib = library.Paths
		}
	}
	if len(stdlib) != 1 || stdlib[0] != "/usr/local/bin/app" {
		t.Fatalf("stdlib found in %v, want only /usr/local/bin/app", stdlib)
	}
}
