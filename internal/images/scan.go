package images

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/containers"
	"deaconguard/internal/store"
)

// maxCacheBytes bounds the layer cache; the least recently used layers go first.
const maxCacheBytes = 2 << 30

// Read fetches an image for platform and reads what is installed in it, as
// the running-container check reads a container. progress, if set, hears
// about each layer.
func Read(ctx context.Context, client *Client, ref Reference, platform string, progress func(string)) (containers.Inventory, Resolved, error) {
	say := func(format string, arguments ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, arguments...))
		}
	}
	resolved, err := client.Resolve(ctx, ref, platform)
	if err != nil {
		return containers.Inventory{}, Resolved{}, err
	}
	say("%s is %s for %s, %d layers", ref, resolved.Digest, platform, len(resolved.Layers))
	fs := newFileSystem()
	skipped := 0
	for index, layer := range resolved.Layers {
		files, cached := loadLayer(layer.Digest)
		if !cached {
			say("Reading layer %d of %d (%s, %.1f MB)", index+1, len(resolved.Layers), shortDigest(layer.Digest), float64(layer.Size)/(1<<20))
			blob, err := client.Blob(ctx, ref, layer)
			if err != nil {
				return containers.Inventory{}, Resolved{}, err
			}
			files, err = readLayer(ctx, blob, layer.MediaType)
			if checked, ok := blob.(interface{ Verify() error }); ok && err == nil {
				err = checked.Verify()
			}
			blob.Close()
			if err != nil {
				return containers.Inventory{}, Resolved{}, fmt.Errorf("layer %s: %w", shortDigest(layer.Digest), err)
			}
			saveLayer(layer.Digest, files)
		}
		skipped += files.Skipped
		fs.apply(files)
	}
	inventory := containers.ReadFS(fs, containers.Container{
		ID: resolved.Digest, Name: ref.String(), Image: ref.String(), ImageID: resolved.Digest, Runtime: "registry",
	})
	if skipped > 0 {
		inventory.Notes = append(inventory.Notes, fmt.Sprintf("%d files were larger than DeaconGuard reads, or over the limit of files, and were skipped", skipped))
	}
	return inventory, resolved, nil
}

func shortDigest(digest string) string {
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func cacheDir() string { return filepath.Join(store.DataDir(), "feeds", "layers") }

func cachePath(digest string) string {
	return filepath.Join(cacheDir(), strings.TrimPrefix(digest, "sha256:")+".json.gz")
}

// loadLayer returns what was read from a layer before. Layers are named by
// the digest of their contents, so a cached one never goes stale.
func loadLayer(digest string) (layerFiles, bool) {
	if !digestPattern.MatchString(digest) {
		return layerFiles{}, false
	}
	file, err := os.Open(cachePath(digest))
	if err != nil {
		return layerFiles{}, false
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return layerFiles{}, false
	}
	var files layerFiles
	if err := json.NewDecoder(reader).Decode(&files); err != nil {
		return layerFiles{}, false
	}
	now := time.Now()
	os.Chtimes(cachePath(digest), now, now)
	return files, true
}

func saveLayer(digest string, files layerFiles) {
	if !digestPattern.MatchString(digest) || os.MkdirAll(cacheDir(), 0o700) != nil {
		return
	}
	temporary, err := os.CreateTemp(cacheDir(), "layer-*")
	if err != nil {
		return
	}
	writer := gzip.NewWriter(temporary)
	err = json.NewEncoder(writer).Encode(files)
	if closeErr := writer.Close(); err == nil {
		err = closeErr
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil || os.Rename(temporary.Name(), cachePath(digest)) != nil {
		os.Remove(temporary.Name())
		return
	}
	pruneCache()
}

// pruneCache keeps the cache under maxCacheBytes.
func pruneCache() {
	entries, err := os.ReadDir(cacheDir())
	if err != nil {
		return
	}
	type cached struct {
		path string
		size int64
		used time.Time
	}
	var all []cached
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !strings.HasSuffix(entry.Name(), ".json.gz") {
			continue
		}
		all = append(all, cached{filepath.Join(cacheDir(), entry.Name()), info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used.Before(all[j].used) })
	for _, c := range all {
		if total <= maxCacheBytes {
			break
		}
		if os.Remove(c.path) == nil {
			total -= c.size
		}
	}
}
