package images

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"deaconguard/internal/containers"
)

// Local images: a `docker save` archive, an OCI image layout (a folder or a
// tar of one, as `docker buildx build --output type=oci` writes), or a folder
// of files, such as a root file system or a project. They are read as data,
// as registry images are; nothing is run.

// Source prefixes say what a local path holds; without one, ReadLocal
// looks.
const (
	SourceDockerArchive = "docker-archive:"
	SourceOCI           = "oci:"
	SourceDir           = "dir:"
)

// IsLocal reports whether an image argument names a local image rather than
// one in a registry: it has a source prefix, or it is a path that exists
// and looks like one (it has a slash, or ends in .tar or .tar.gz).
func IsLocal(argument string) bool {
	for _, prefix := range []string{SourceDockerArchive, SourceOCI, SourceDir} {
		if strings.HasPrefix(argument, prefix) {
			return true
		}
	}
	if !strings.ContainsRune(argument, '/') && !strings.HasSuffix(argument, ".tar") && !strings.HasSuffix(argument, ".tar.gz") &&
		!strings.HasSuffix(argument, ".tgz") && argument != "." {
		return false
	}
	_, err := os.Stat(argument)
	return err == nil
}

// archive is a folder or a tar file of an image's files.
type archive interface {
	open(name string) (io.ReadCloser, error)
	has(name string) bool
	Close() error
}

type folder string

func (f folder) open(name string) (io.ReadCloser, error) {
	clean := path.Clean("/" + name)
	return os.Open(filepath.Join(string(f), filepath.FromSlash(clean)))
}

func (f folder) has(name string) bool {
	info, err := os.Stat(filepath.Join(string(f), filepath.FromSlash(path.Clean("/"+name))))
	return err == nil && info.Mode().IsRegular()
}

func (folder) Close() error { return nil }

// indexedTar is a tar archive, indexed so its files can be read in any order.
type indexedTar struct {
	file    *os.File
	entries map[string][2]int64 // offset and size
	cleanup string
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// openTar indexes a tar file; a gzip-compressed one is first unpacked to a
// temporary file, which Close removes.
func openTar(name string) (*indexedTar, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	t := &indexedTar{file: file, entries: map[string][2]int64{}}
	magic := make([]byte, 2)
	if n, _ := io.ReadFull(file, magic); n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		file.Seek(0, io.SeekStart)
		unpacked, err := os.CreateTemp("", "deaconguard-image-*.tar")
		if err != nil {
			file.Close()
			return nil, err
		}
		t.cleanup = unpacked.Name()
		gz, err := gzip.NewReader(bufio.NewReader(file))
		if err == nil {
			_, err = io.Copy(unpacked, io.LimitReader(gz, 4*maxLayerBytes))
		}
		file.Close()
		t.file = unpacked
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("unpack %s: %w", name, err)
		}
	}
	if _, err := t.file.Seek(0, io.SeekStart); err != nil {
		t.Close()
		return nil, err
	}
	counter := &countingReader{r: t.file}
	reader := tar.NewReader(counter)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("%s is not a tar archive: %w", name, err)
		}
		if header.Typeflag == tar.TypeReg {
			// tar reads whole blocks and no further, so the data starts here.
			t.entries[path.Clean("/"+header.Name)] = [2]int64{counter.n, header.Size}
		}
	}
	return t, nil
}

func (t *indexedTar) open(name string) (io.ReadCloser, error) {
	entry, ok := t.entries[path.Clean("/"+name)]
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, fs.ErrNotExist)
	}
	return io.NopCloser(io.NewSectionReader(t.file, entry[0], entry[1])), nil
}

func (t *indexedTar) has(name string) bool {
	_, ok := t.entries[path.Clean("/"+name)]
	return ok
}

func (t *indexedTar) Close() error {
	err := t.file.Close()
	if t.cleanup != "" {
		os.Remove(t.cleanup)
	}
	return err
}

// ReadLocal reads a local image, or a folder, for platform, and what is
// installed in it.
func ReadLocal(ctx context.Context, source, platform string, progress func(string)) (containers.Inventory, Resolved, error) {
	say := func(format string, arguments ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, arguments...))
		}
	}
	kind, name := "", source
	for _, prefix := range []string{SourceDockerArchive, SourceOCI, SourceDir} {
		if strings.HasPrefix(source, prefix) {
			kind, name = prefix, strings.TrimPrefix(source, prefix)
		}
	}
	info, err := os.Stat(name)
	if err != nil {
		return containers.Inventory{}, Resolved{}, err
	}
	var files archive
	if info.IsDir() {
		files = folder(name)
	} else if kind == SourceDir {
		return containers.Inventory{}, Resolved{}, fmt.Errorf("%s is not a folder", name)
	} else {
		say("Indexing %s", name)
		t, err := openTar(name)
		if err != nil {
			return containers.Inventory{}, Resolved{}, err
		}
		files = t
	}
	defer files.Close()
	if kind == "" {
		switch {
		case files.has("manifest.json"):
			kind = SourceDockerArchive
		case files.has("index.json") && files.has("oci-layout"):
			kind = SourceOCI
		case info.IsDir():
			kind = SourceDir
		default:
			return containers.Inventory{}, Resolved{}, fmt.Errorf("%s is neither a docker save archive nor an OCI image layout", name)
		}
	}
	switch kind {
	case SourceDir:
		return readFolder(ctx, name, platform, say)
	case SourceDockerArchive:
		return readDockerArchive(ctx, files, name, platform, say)
	default:
		return readOCILayout(ctx, files, name, platform, say)
	}
}

func readJSON(files archive, name string, limit int64, value any) error {
	reader, err := files.open(name)
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("%s is larger than %d MB", name, limit>>20)
	}
	return json.Unmarshal(data, value)
}

// blobPath is where an OCI layout keeps a blob.
func blobPath(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("unsupported digest %q", digest)
	}
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:"), nil
}

// readBlobJSON reads a blob by digest and checks it.
func readBlobJSON(files archive, digest string, value any) error {
	name, err := blobPath(digest)
	if err != nil {
		return err
	}
	reader, err := files.open(name)
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxManifestBytes {
		return fmt.Errorf("%s is larger than 4 MB", name)
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("%s doesn't match its digest", name)
	}
	return json.Unmarshal(data, value)
}

func readOCILayout(ctx context.Context, files archive, name, platform string, say func(string, ...any)) (containers.Inventory, Resolved, error) {
	var index struct {
		manifest
		Manifests []struct {
			Descriptor
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := readJSON(files, "index.json", maxManifestBytes, &index); err != nil {
		return containers.Inventory{}, Resolved{}, fmt.Errorf("read the OCI layout's index.json: %w", err)
	}
	title := filepath.Base(name)
	top := manifest{MediaType: mediaOCIIndex}
	for _, d := range index.Manifests {
		top.Manifests = append(top.Manifests, d.Descriptor)
		if ref := d.Annotations["io.containerd.image.name"]; ref != "" && title == filepath.Base(name) {
			title = ref
		}
		// The OCI ref name is often only a tag, as skopeo writes it: name it
		// after the layout, as layout:tag.
		if ref := d.Annotations["org.opencontainers.image.ref.name"]; ref != "" && title == filepath.Base(name) {
			title = ref
			if !strings.ContainsAny(ref, "/:") {
				title = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(name), ".tar"), ".tar.gz") + ":" + ref
			}
		}
	}
	// index.json may point at an image index (several platforms) or at
	// images directly; follow indexes until an image manifest.
	current, mediaType := top, mediaOCIIndex
	digest, tagDigest := "", ""
	for depth := 0; current.isIndex(mediaType); depth++ {
		if depth > 3 {
			return containers.Inventory{}, Resolved{}, errors.New("the OCI layout nests indexes too deeply")
		}
		chosen, err := current.choose(platform, title)
		if err != nil {
			return containers.Inventory{}, Resolved{}, err
		}
		if tagDigest == "" {
			tagDigest = chosen.Digest
		}
		var next manifest
		if err := readBlobJSON(files, chosen.Digest, &next); err != nil {
			return containers.Inventory{}, Resolved{}, err
		}
		current, mediaType, digest = next, chosen.MediaType, chosen.Digest
	}
	if len(current.Layers) == 0 {
		return containers.Inventory{}, Resolved{}, fmt.Errorf("%s has no layers", title)
	}
	return readLayers(ctx, files, title, Resolved{Digest: digest, TagDigest: tagDigest, Platform: platform, Layers: current.Layers}, say)
}

func readDockerArchive(ctx context.Context, files archive, name, platform string, say func(string, ...any)) (containers.Inventory, Resolved, error) {
	var images []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if err := readJSON(files, "manifest.json", 1<<20, &images); err != nil {
		return containers.Inventory{}, Resolved{}, fmt.Errorf("read the archive's manifest.json: %w", err)
	}
	if len(images) == 0 || len(images[0].Layers) == 0 {
		return containers.Inventory{}, Resolved{}, errors.New("the archive's manifest.json lists no image")
	}
	image := images[0]
	title := filepath.Base(name)
	if len(image.RepoTags) > 0 {
		title = image.RepoTags[0]
	}
	if len(images) > 1 {
		say("The archive holds %d images; checking the first, %s", len(images), title)
	}
	// The image ID is its config's digest: the file name, in either layout.
	id := strings.TrimSuffix(path.Base(image.Config), ".json")
	resolved := Resolved{Digest: "sha256:" + id, TagDigest: "sha256:" + id, Platform: platform}
	for _, layer := range image.Layers {
		// Docker 25 and later save an OCI layout, with layers under
		// blobs/sha256 by digest; older archives have <id>/layer.tar.
		digest := ""
		if hexDigest, ok := strings.CutPrefix(path.Clean("/"+layer), "/blobs/sha256/"); ok {
			digest = "sha256:" + hexDigest
		}
		resolved.Layers = append(resolved.Layers, Descriptor{Digest: digest, MediaType: layer})
	}
	return readLayers(ctx, files, title, resolved, say)
}

// readLayers applies an image's layers in order. Layers named by digest are
// checked against it and cached; old docker archives name them otherwise.
func readLayers(ctx context.Context, files archive, title string, resolved Resolved, say func(string, ...any)) (containers.Inventory, Resolved, error) {
	say("%s: %d layers", title, len(resolved.Layers))
	fsys := newFileSystem()
	skipped := 0
	for index, layer := range resolved.Layers {
		read, cached := layerFiles{}, false
		if layer.Digest != "" {
			read, cached = loadLayer(layer.Digest)
		}
		if !cached {
			name := layer.MediaType // an old archive's layer path
			if layer.Digest != "" {
				var err error
				if name, err = blobPath(layer.Digest); err != nil {
					return containers.Inventory{}, Resolved{}, err
				}
			}
			say("Reading layer %d of %d", index+1, len(resolved.Layers))
			reader, err := files.open(name)
			if err != nil {
				return containers.Inventory{}, Resolved{}, fmt.Errorf("layer %d: %w", index+1, err)
			}
			var stream io.Reader = reader
			var check *verified
			if layer.Digest != "" {
				check = &verified{ReadCloser: reader, hash: sha256.New(), want: strings.TrimPrefix(layer.Digest, "sha256:")}
				stream = check
			}
			read, err = readLayer(ctx, stream, "")
			if check != nil && err == nil {
				err = check.Verify()
			}
			reader.Close()
			if err != nil {
				return containers.Inventory{}, Resolved{}, fmt.Errorf("layer %d: %w", index+1, err)
			}
			if layer.Digest != "" {
				saveLayer(layer.Digest, read)
			}
		}
		skipped += read.Skipped
		fsys.apply(read)
	}
	inventory := containers.ReadFS(fsys, containers.Container{
		ID: resolved.Digest, Name: title, Image: title, ImageID: resolved.Digest, Runtime: "local",
	})
	if skipped > 0 {
		inventory.Notes = append(inventory.Notes, fmt.Sprintf("%d files were larger than DeaconGuard reads, or over the limit of files, and were skipped", skipped))
	}
	return inventory, resolved, nil
}

// onPackagePath reports whether a package database is in the folder dir.
func onPackagePath(dir string) bool {
	if strings.HasPrefix("/var/lib/dpkg/status.d", dir+"/") || dir == "/var/lib/dpkg/status.d" {
		return true
	}
	for _, file := range containers.PackageFiles {
		if strings.HasPrefix(file, dir+"/") {
			return true
		}
	}
	return false
}

// maxFolderEntries bounds the walk of a folder.
const maxFolderEntries = 2_000_000

// readFolder reads a folder as an image's file system: a root file system
// (a built image's files, a chroot) or a project with lock files. Symbolic
// links are never followed on disk; links among the files read are resolved
// within the folder.
func readFolder(ctx context.Context, root, platform string, say func(string, ...any)) (containers.Inventory, Resolved, error) {
	say("Reading the files in %s", root)
	layer := layerFiles{Files: map[string][]byte{}, Links: map[string]string{}}
	entries := 0
	var restricted []string
	err := filepath.WalkDir(root, func(full string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: left out
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entries++; entries > maxFolderEntries {
			return fmt.Errorf("%s has more than %d files and folders", root, maxFolderEntries)
		}
		rel, err := filepath.Rel(root, full)
		if err != nil || rel == "." {
			return nil
		}
		name := "/" + filepath.ToSlash(rel)
		if entry.IsDir() {
			// Folders the library check skips, such as /usr/lib, are entered
			// only on the way to a package database, such as
			// /usr/lib/os-release or /usr/lib/sysimage/rpm.
			dir, base := path.Split(name)
			inside := false
			for _, prefix := range restricted {
				inside = inside || strings.HasPrefix(name, prefix+"/")
			}
			if inside || containers.SkippedDir(strings.TrimSuffix(dir, "/"), base) {
				if !onPackagePath(name) {
					return filepath.SkipDir
				}
				if !inside {
					restricted = append(restricted, name)
				}
			}
			return nil
		}
		wanted, limit := wantedFile(name)
		if !wanted {
			return nil
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			if target, err := os.Readlink(full); err == nil {
				layer.Links[name] = filepath.ToSlash(target)
			}
		case entry.Type().IsRegular():
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			if info.Size() > limit || len(layer.Files) >= maxFiles {
				layer.Skipped++
				return nil
			}
			data, err := os.ReadFile(full)
			if err == nil {
				layer.Files[name] = data
			}
		}
		return nil
	})
	if err != nil {
		return containers.Inventory{}, Resolved{}, err
	}
	fsys := newFileSystem()
	fsys.apply(layer)
	title := filepath.Base(filepath.Clean(root))
	if abs, err := filepath.Abs(root); err == nil {
		title = abs
	}
	inventory := containers.ReadFS(fsys, containers.Container{Name: title, Image: title, Runtime: "local"})
	if layer.Skipped > 0 {
		inventory.Notes = append(inventory.Notes, fmt.Sprintf("%d files were larger than DeaconGuard reads, or over the limit of files, and were skipped", layer.Skipped))
	}
	return inventory, Resolved{Platform: platform}, nil
}
