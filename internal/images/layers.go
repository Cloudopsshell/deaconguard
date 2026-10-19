package images

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"

	"deaconguard/internal/containers"
	"deaconguard/internal/libraries"
)

// Limits for one image.
const (
	maxLayerBytes = 8 << 30
	maxFileBytes  = 128 << 20
	maxFiles      = 20000
)

// layerFiles is what one layer holds of the files DeaconGuard reads, and
// what it deletes from the layers below.
type layerFiles struct {
	Files   map[string][]byte `json:"files"`
	Links   map[string]string `json:"links"`
	Deleted []string          `json:"deleted"`
	Opaque  []string          `json:"opaque"`
	Skipped int               `json:"skipped,omitempty"`
}

// wantedFile reports whether a path in an image is read, and at most how
// many bytes of it.
func wantedFile(name string) (bool, int64) {
	for _, p := range containers.PackageFiles {
		if name == p {
			if strings.HasSuffix(name, "rpmdb.sqlite") {
				return true, maxFileBytes
			}
			return true, 32 << 20
		}
	}
	if strings.HasPrefix(name, "/var/lib/dpkg/status.d/") {
		return true, 1 << 20
	}
	if containers.LibraryFile(name) {
		return true, libraries.MaxFileBytes
	}
	return false, 0
}

// readLayer reads a layer's tar stream, compressed or not.
func readLayer(ctx context.Context, stream io.Reader, mediaType string) (layerFiles, error) {
	buffered := bufio.NewReaderSize(stream, 64<<10)
	var reader io.Reader = buffered
	magic, _ := buffered.Peek(4)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return layerFiles{}, err
		}
		defer gz.Close()
		reader = gz
	case len(magic) == 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		zr, err := zstd.NewReader(buffered)
		if err != nil {
			return layerFiles{}, err
		}
		defer zr.Close()
		reader = zr
	}
	layer := layerFiles{Files: map[string][]byte{}, Links: map[string]string{}}
	archive := tar.NewReader(io.LimitReader(reader, maxLayerBytes))
	for {
		if err := ctx.Err(); err != nil {
			return layer, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return layer, fmt.Errorf("read the layer: %w", err)
		}
		name := path.Clean("/" + header.Name)
		dir, base := path.Split(name)
		// OCI whiteouts: .wh.<name> deletes <name> below; .wh..wh..opq
		// empties the directory below.
		if base == ".wh..wh..opq" {
			layer.Opaque = append(layer.Opaque, strings.TrimSuffix(dir, "/"))
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			layer.Deleted = append(layer.Deleted, path.Join(dir, strings.TrimPrefix(base, ".wh.")))
			continue
		}
		wanted, limit := wantedFile(name)
		if !wanted {
			continue
		}
		switch header.Typeflag {
		case tar.TypeSymlink:
			layer.Links[name] = header.Linkname
		case tar.TypeLink:
			layer.Links[name] = "/" + strings.TrimPrefix(path.Clean("/"+header.Linkname), "/")
		case tar.TypeReg:
			if header.Size > limit {
				layer.Skipped++
				continue
			}
			if len(layer.Files) >= maxFiles {
				layer.Skipped++
				continue
			}
			data, err := io.ReadAll(io.LimitReader(archive, limit))
			if err != nil {
				return layer, fmt.Errorf("read %s: %w", name, err)
			}
			layer.Files[name] = data
		}
	}
	// Read the rest of the stream, so the digest can be checked (see
	// verified.Verify); errors here show again there.
	io.Copy(io.Discard, reader)
	io.Copy(io.Discard, buffered)
	return layer, nil
}

// fileSystem is an image's files, layers applied in order, as containers.FS.
type fileSystem struct {
	files map[string][]byte
	links map[string]string
}

func newFileSystem() *fileSystem {
	return &fileSystem{files: map[string][]byte{}, links: map[string]string{}}
}

// apply adds a layer on top.
func (fs *fileSystem) apply(layer layerFiles) {
	for _, dir := range layer.Opaque {
		fs.removeUnder(dir)
	}
	for _, name := range layer.Deleted {
		delete(fs.files, name)
		delete(fs.links, name)
		fs.removeUnder(name)
	}
	for name, data := range layer.Files {
		delete(fs.links, name)
		fs.files[name] = data
	}
	for name, target := range layer.Links {
		delete(fs.files, name)
		fs.links[name] = target
	}
}

func (fs *fileSystem) removeUnder(dir string) {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for name := range fs.files {
		if strings.HasPrefix(name, prefix) {
			delete(fs.files, name)
		}
	}
	for name := range fs.links {
		if strings.HasPrefix(name, prefix) {
			delete(fs.links, name)
		}
	}
}

// resolve follows links inside the image, which is only data here.
func (fs *fileSystem) resolve(name string) (string, bool) {
	for hops := 0; hops < 40; hops++ {
		if _, ok := fs.files[name]; ok {
			return name, true
		}
		target, ok := fs.links[name]
		if !ok {
			return "", false
		}
		if !strings.HasPrefix(target, "/") {
			target = path.Join(path.Dir(name), target)
		}
		name = path.Clean(target)
	}
	return "", false
}

func (fs *fileSystem) ReadFile(name string, limit int64) ([]byte, bool, error) {
	resolved, ok := fs.resolve(path.Clean(name))
	if !ok {
		return nil, false, fmt.Errorf("%s: not in the image", name)
	}
	data := fs.files[resolved]
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func (fs *fileSystem) ReadDir(dir string) ([]containers.Entry, error) {
	prefix := strings.TrimSuffix(path.Clean(dir), "/") + "/"
	seen := map[string]containers.Entry{}
	for name, data := range fs.files {
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		first, more, isDir := strings.Cut(rest, "/")
		_ = more
		if isDir {
			seen[first] = containers.Entry{Name: first, IsDir: true}
		} else {
			seen[first] = containers.Entry{Name: first, IsReg: true, Size: int64(len(data))}
		}
	}
	if len(seen) == 0 && dir != "/" {
		return nil, fmt.Errorf("%s: not in the image", dir)
	}
	entries := make([]containers.Entry, 0, len(seen))
	for _, entry := range seen {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func (fs *fileSystem) Device() uint64 { return 0 }
