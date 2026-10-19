package images

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFiles writes files under dir.
func writeFiles(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// tarOf packs files into a tar, gzip-compressed if asked.
func tarOf(t *testing.T, files map[string][]byte, compress bool) []byte {
	t.Helper()
	var raw bytes.Buffer
	var w = &raw
	var gz *gzip.Writer
	tw := tar.NewWriter(w)
	if compress {
		gz = gzip.NewWriter(w)
		tw = tar.NewWriter(gz)
	}
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	tw.Close()
	if gz != nil {
		gz.Close()
	}
	return raw.Bytes()
}

func blob(files map[string][]byte, data []byte) string {
	digest := digestOf(data)
	files["blobs/sha256/"+strings.TrimPrefix(digest, "sha256:")] = data
	return digest
}

func testLayers(t *testing.T) (base, app []byte) {
	base = layer(t,
		tarFile{name: "etc/os-release", body: "ID=debian\nVERSION_ID=12\n"},
		tarFile{name: "var/lib/dpkg/status", body: "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\n\n"},
	)
	app = layer(t, tarFile{name: "app/package-lock.json", body: `{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`})
	return base, app
}

// ociLayout is a two-platform image as `docker buildx build --output type=oci` writes it.
func ociLayout(t *testing.T) map[string][]byte {
	base, app := testLayers(t)
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	layers := []map[string]any{
		{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": blob(files, base), "size": len(base)},
		{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": blob(files, app), "size": len(app)},
	}
	amd64, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "layers": layers})
	arm64, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "layers": layers[:1]})
	list, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex, "manifests": []map[string]any{
		{"mediaType": mediaOCIManifest, "digest": blob(files, amd64), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		{"mediaType": mediaOCIManifest, "digest": blob(files, arm64), "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
	}})
	files["index.json"], _ = json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{
		{"mediaType": mediaOCIIndex, "digest": blob(files, list), "annotations": map[string]string{"io.containerd.image.name": "acme/shop:4.2"}},
	}})
	return files
}

func TestReadOCILayout(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	files := ociLayout(t)
	dir := t.TempDir()
	writeFiles(t, filepath.Join(dir, "layout"), files)
	archive := filepath.Join(dir, "image.tar")
	os.WriteFile(archive, tarOf(t, files, false), 0o644)
	compressed := filepath.Join(dir, "image.tar.gz")
	os.WriteFile(compressed, tarOf(t, files, true), 0o644)

	for _, source := range []string{filepath.Join(dir, "layout"), "oci:" + archive, compressed} {
		inventory, resolved, err := ReadLocal(context.Background(), source, "linux/amd64", nil)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if inventory.Name != "acme/shop:4.2" || !strings.Contains(inventory.DPKGStatus, "openssl") || len(resolved.Layers) != 2 ||
			inventory.Libraries == nil || len(inventory.Libraries.Libraries) != 1 || inventory.Runtime != "local" {
			t.Errorf("%s: %+v, %+v", source, inventory, resolved)
		}
	}
	if inventory, resolved, err := ReadLocal(context.Background(), compressed, "linux/arm64", nil); err != nil || len(resolved.Layers) != 1 || inventory.Libraries != nil && len(inventory.Libraries.Libraries) > 0 {
		t.Errorf("arm64: %+v, %v", resolved, err)
	}
	if _, _, err := ReadLocal(context.Background(), compressed, "linux/s390x", nil); err == nil || !strings.Contains(err.Error(), "linux/amd64, linux/arm64") {
		t.Errorf("a missing platform: %v", err)
	}

	// A layer that doesn't match its digest is refused.
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	tampered := map[string][]byte{}
	for name, data := range files {
		tampered[name] = data
	}
	base, _ := testLayers(t)
	evil := layer(t, tarFile{name: "etc/os-release", body: "ID=alpine\n"})
	tampered["blobs/sha256/"+strings.TrimPrefix(digestOf(base), "sha256:")] = evil
	os.WriteFile(archive, tarOf(t, tampered, false), 0o644)
	if _, _, err := ReadLocal(context.Background(), archive, "linux/amd64", nil); err == nil || !strings.Contains(err.Error(), "doesn't match its digest") {
		t.Errorf("a tampered layer: %v", err)
	}
}

func TestReadDockerArchive(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	base, app := testLayers(t)
	// An archive from docker save before Docker 25: layers as <id>/layer.tar, uncompressed.
	plain := func(gzipped []byte) []byte {
		gz, err := gzip.NewReader(bytes.NewReader(gzipped))
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		out.ReadFrom(gz)
		return out.Bytes()
	}
	old := map[string][]byte{
		"0123/layer.tar": plain(base),
		"4567/layer.tar": plain(app),
		"89ab.json":      []byte(`{"architecture":"amd64"}`),
	}
	old["manifest.json"], _ = json.Marshal([]map[string]any{{"Config": "89ab.json", "RepoTags": []string{"shop:old"}, "Layers": []string{"0123/layer.tar", "4567/layer.tar"}}})
	// From Docker 25: the same, in an OCI layout.
	current := ociLayout(t)
	baseDigest, appDigest := digestOf(base), digestOf(app)
	current["manifest.json"], _ = json.Marshal([]map[string]any{{"Config": "blobs/sha256/" + strings.Repeat("c", 64), "RepoTags": []string{"shop:new"},
		"Layers": []string{"blobs/sha256/" + strings.TrimPrefix(baseDigest, "sha256:"), "blobs/sha256/" + strings.TrimPrefix(appDigest, "sha256:")}}})

	dir := t.TempDir()
	for name, files := range map[string]map[string][]byte{"shop:old": old, "shop:new": current} {
		archive := filepath.Join(dir, strings.ReplaceAll(name, ":", "-")+".tar")
		os.WriteFile(archive, tarOf(t, files, false), 0o644)
		inventory, resolved, err := ReadLocal(context.Background(), archive, "linux/amd64", nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if inventory.Name != name || !strings.Contains(inventory.OSRelease, "debian") || len(inventory.Libraries.Libraries) != 1 || !strings.HasPrefix(resolved.Digest, "sha256:") {
			t.Errorf("%s: %+v %+v", name, inventory, resolved)
		}
	}
}

func TestReadFolder(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string][]byte{
		"usr/lib/os-release":                             []byte("ID=alpine\nVERSION_ID=3.22.1\n"),
		"usr/lib/python3/dist-packages/requirements.txt": []byte("left-out==1.0\n"),
		"lib/apk/db/installed":                           []byte("P:musl\nV:1.2.5-r10\n\n"),
		"srv/app/requirements.txt":                       []byte("django==3.2.0\n"),
		"srv/app/.git/requirements.txt":                  []byte("flask==0.1\n"),
		"srv/app/node_modules/x/package-lock.json":       []byte(`{"packages":{"node_modules/y":{"version":"1.0.0"}}}`),
		"proc/1/environ":                                 []byte("SECRET=1"),
	})
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.Symlink("../usr/lib/os-release", filepath.Join(dir, "etc", "os-release"))
	// A link out of the folder is never followed on disk.
	os.Symlink("/etc/passwd", filepath.Join(dir, "srv", "app", "package-lock.json"))

	inventory, _, err := ReadLocal(context.Background(), "dir:"+dir, "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inventory.OSRelease, "alpine") || !strings.Contains(inventory.APKInstalled, "musl") {
		t.Errorf("os-release through its link = %q, apk = %q", inventory.OSRelease, inventory.APKInstalled)
	}
	if inventory.Libraries == nil || len(inventory.Libraries.Libraries) != 1 || inventory.Libraries.Libraries[0].Name != "django" {
		t.Errorf("libraries = %+v; .git and node_modules are skipped, and the outside link isn't read", inventory.Libraries)
	}
	if !IsLocal(dir) || !IsLocal("dir:"+dir) || IsLocal("nginx:1.27") || IsLocal("ghcr.io/acme/shop:4.2") {
		t.Error("IsLocal")
	}
	if _, _, err := ReadLocal(context.Background(), "dir:"+filepath.Join(dir, "lib", "apk", "db", "installed"), "linux/amd64", nil); err == nil {
		t.Error("dir: of a file")
	}
}
