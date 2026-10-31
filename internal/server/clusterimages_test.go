package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/containers"
	"deaconguard/internal/images"
)

func TestClusterImagesAreReadOnceADay(t *testing.T) {
	s := newNetworkTestServer(t)
	var asked []string
	s.images.read = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
		asked = append(asked, ref.String()+" "+platform)
		if ref.Repository == "acme/private" {
			return containers.Inventory{}, images.Resolved{}, images.ErrUnauthorized
		}
		return containers.Inventory{Container: containers.Container{Name: ref.String(), Runtime: "registry"}}, images.Resolved{}, nil
	}
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	cache := newClusterImages(s)
	cache.now = func() time.Time { return now }
	digest := "sha256:" + strings.Repeat("e", 64)
	nginx := checks.RunningImage{Image: "nginx:1.27", Digest: digest}
	private := checks.RunningImage{Image: "ghcr.io/acme/private:1"}

	if _, _, found := cache.Cached(nginx, "linux/arm64"); found {
		t.Fatal("cached before any read")
	}
	if _, err := cache.Check(context.Background(), nginx, "linux/arm64"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Check(context.Background(), private, "linux/arm64"); !errors.Is(err, images.ErrUnauthorized) {
		t.Fatalf("private: %v", err)
	}
	// The build is read by its digest.
	if len(asked) != 2 || !strings.Contains(asked[0], "@"+digest) {
		t.Fatalf("asked = %v", asked)
	}
	// The same build under another tag, or another repository, is the same.
	if _, _, found := cache.Cached(checks.RunningImage{Image: "mirror.example/nginx:stable", Digest: digest}, "linux/arm64"); !found {
		t.Fatal("same digest not cached")
	}
	if _, _, found := cache.Cached(nginx, "linux/amd64"); found {
		t.Fatal("another platform cached")
	}
	now = now.Add(30 * time.Minute)
	if _, err, found := cache.Cached(private, "linux/arm64"); !found || err == nil {
		t.Fatal("a failure isn't kept for an hour")
	}
	now = now.Add(time.Hour)
	if _, _, found := cache.Cached(private, "linux/arm64"); found {
		t.Fatal("a failure is kept over an hour")
	}
	if _, _, found := cache.Cached(nginx, "linux/arm64"); !found {
		t.Fatal("a result isn't kept for a day")
	}
	now = now.Add(23 * time.Hour)
	if _, _, found := cache.Cached(nginx, "linux/arm64"); found {
		t.Fatal("a result is kept over a day")
	}
}

func TestClusterImageCacheStaysBounded(t *testing.T) {
	cache := &clusterImages{now: time.Now, entries: map[string]clusterImageEntry{}}
	start := time.Now().Add(-time.Hour)
	for i := 0; i < maxClusterImageEntries+50; i++ {
		cache.keep(string(rune(i+1))+"key", clusterImageEntry{at: start.Add(time.Duration(i) * time.Second)})
	}
	if len(cache.entries) != maxClusterImageEntries {
		t.Fatalf("entries = %d", len(cache.entries))
	}
}
