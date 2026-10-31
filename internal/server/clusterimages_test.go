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
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
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

func TestClusterImagesComeFromNodeAgentsFirst(t *testing.T) {
	s := newNetworkTestServer(t)
	read := 0
	s.images.read = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
		read++
		return containers.Inventory{Container: containers.Container{Name: ref.String(), Runtime: "registry"}}, images.Resolved{}, nil
	}
	digest := "sha256:" + strings.Repeat("f", 64)
	other := "sha256:" + strings.Repeat("1", 64)
	node, _ := store.AddLocalHost("node-1", "root")
	nginx := container("shop/web/nginx", "nginx:1.25", containerCVE("CVE-2023-44487", "HIGH", true, true))
	nginx["image_id"], nginx["fixable"], nginx["exploited"] = "docker.io/library/nginx@"+digest, 1, 1
	nginx["severity"], nginx["fixable_severity"] = map[string]int{"HIGH": 1}, map[string]int{"HIGH": 1}
	stopped := container("tools/old/sh", "busybox:1")
	stopped["image_id"], stopped["state"] = "docker.io/library/busybox@"+other, "exited"
	completeChecks(t, node, map[string]any{checks.Containers: containerResult(nginx, stopped)})

	// A restarted server finds the node agent's scan of the last day.
	cache := newClusterImages(s)
	summary, err, found := cache.Cached(checks.RunningImage{Image: "nginx:1.25", Digest: digest}, "linux/amd64")
	if !found || err != nil || summary.Node != "node-1" || summary.Exploited != 1 || summary.Urgent[0] != "CVE-2023-44487" {
		t.Fatalf("from the node: %+v, %v, %v", summary, err, found)
	}
	// A stopped container wasn't read, so its build isn't known.
	if _, _, found := cache.Cached(checks.RunningImage{Image: "busybox:1", Digest: other}, "linux/amd64"); found {
		t.Fatal("a stopped container's image counted as read")
	}
	if read != 0 {
		t.Fatalf("read %d images from registries", read)
	}

	// Agents' new scans are recorded as they arrive.
	fresh := newClusterImages(s)
	fresh.warm.Do(func() {})
	report := map[string]any{"check_results": map[string]any{checks.Containers: containerResult(nginx)}}
	fresh.recordNode(node, report)
	if summary, _, found := fresh.Cached(checks.RunningImage{Image: "nginx:1.25", Digest: digest}, "linux/arm64"); !found || summary.Node != "node-1" {
		t.Fatalf("recorded: %+v %v", summary, found)
	}

	// With registry reads off, the rest aren't read.
	t.Setenv("DEACONGUARD_CLUSTER_IMAGE_REGISTRY", "off")
	off := newClusterImages(s)
	if _, err := off.Check(context.Background(), checks.RunningImage{Image: "redis:7"}, "linux/amd64"); !errors.Is(err, scan.ErrRegistryOff) || read != 0 {
		t.Fatalf("off: %v, read %d", err, read)
	}
}
