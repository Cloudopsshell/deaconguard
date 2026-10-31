package server

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/images"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

// The images clusters run are checked on the server (scan.EvaluateClusterImages).
// A build a node agent already read from a running container, in a Running
// containers scan of the last day, is taken from that scan: nothing is
// downloaded. Only the others are read from their registries, unless
// DEACONGUARD_CLUSTER_IMAGE_REGISTRY=off. Each result is kept in memory: a build for a day, so new advisories are
// seen daily, and a failure for an hour, so a registry that refuses isn't
// asked again on every scan of a cluster that changes often. A restart
// forgets them; the next scans read the images again.
const (
	clusterImageKept        = 24 * time.Hour
	clusterImageFailureKept = time.Hour
	maxClusterImageEntries  = 2000
)

type clusterImageEntry struct {
	summary scan.ImageSummary
	failure string
	at      time.Time
}

// clusterImages is the server's scan.ClusterImages. Reads go one at a time,
// whatever the number of clusters, so the server never reads several
// images at once for them.
type clusterImages struct {
	server  *Server
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]clusterImageEntry
	reading sync.Mutex
	// registry is off when DEACONGUARD_CLUSTER_IMAGE_REGISTRY is off.
	registry bool
	// warm loads the node agents' recent scans once, after a start.
	warm sync.Once
}

func newClusterImages(s *Server) *clusterImages {
	setting := strings.ToLower(strings.TrimSpace(os.Getenv("DEACONGUARD_CLUSTER_IMAGE_REGISTRY")))
	return &clusterImages{server: s, now: time.Now, entries: map[string]clusterImageEntry{},
		registry: !slices.Contains([]string{"off", "false", "0", "no"}, setting)}
}

// nodeKey identifies a build a node agent read, whatever the platform: a
// node runs its own.
func nodeKey(digest string) string { return "node\x00" + digest }

// recordNode keeps the builds an agent read in a Running containers scan.
func (c *clusterImages) recordNode(host store.Host, report map[string]any) {
	if host.IsCluster() {
		return
	}
	for _, image := range scan.NodeImages(report) {
		image.Summary.Node = host.Address
		c.keep(nodeKey(image.Digest), clusterImageEntry{summary: image.Summary, at: c.now()})
	}
}

// warmUp reads the node agents' Running containers scans of the last day,
// so a restarted server doesn't download what they already read.
func (c *clusterImages) warmUp() {
	hosts, err := store.ListHosts()
	if err != nil {
		return
	}
	since := c.now().Add(-clusterImageKept).UTC().Format(time.RFC3339)
	for _, host := range hosts {
		if host.IsCluster() {
			continue
		}
		scans, err := store.ListScans(host.ID, 20)
		if err != nil {
			continue
		}
		for _, record := range scans {
			if record.StartedAt < since {
				break
			}
			if record.Status != store.ScanSucceeded || !slices.Contains(record.Checks, checks.Containers) {
				continue
			}
			report, err := store.GetFullReport(record.ID)
			if err != nil {
				break
			}
			at, err := time.Parse(time.RFC3339, record.StartedAt)
			if err != nil {
				at = c.now()
			}
			for _, image := range scan.NodeImages(report) {
				image.Summary.Node = host.Address
				c.keep(nodeKey(image.Digest), clusterImageEntry{summary: image.Summary, at: at})
			}
			break
		}
	}
}

// clusterImageKey identifies a build: by its digest when the cluster agent
// sent one, else by its reference, whose tag may move.
func clusterImageKey(image checks.RunningImage, platform string) string {
	if image.Digest != "" {
		return platform + "\x00" + image.Digest
	}
	return platform + "\x00" + image.Image
}

func (c *clusterImages) Cached(image checks.RunningImage, platform string) (scan.ImageSummary, error, bool) {
	c.warm.Do(c.warmUp)
	c.mu.Lock()
	defer c.mu.Unlock()
	if image.Digest != "" {
		if entry, found := c.entries[nodeKey(image.Digest)]; found && c.now().Sub(entry.at) < clusterImageKept {
			return entry.summary, nil, true
		}
	}
	entry, found := c.entries[clusterImageKey(image, platform)]
	if !found {
		return scan.ImageSummary{}, nil, false
	}
	age := c.now().Sub(entry.at)
	if entry.failure != "" {
		if age >= clusterImageFailureKept {
			return scan.ImageSummary{}, nil, false
		}
		return scan.ImageSummary{}, errors.New(entry.failure), true
	}
	if age >= clusterImageKept {
		return scan.ImageSummary{}, nil, false
	}
	return entry.summary, nil, true
}

func (c *clusterImages) Check(ctx context.Context, image checks.RunningImage, platform string) (scan.ImageSummary, error) {
	if !c.registry {
		return scan.ImageSummary{}, scan.ErrRegistryOff
	}
	c.reading.Lock()
	defer c.reading.Unlock()
	summary, err := c.read(ctx, image, platform)
	entry := clusterImageEntry{summary: summary, at: c.now()}
	if err != nil {
		if ctx.Err() != nil {
			// Out of time: not the registry's fault, so not kept.
			return summary, err
		}
		entry.failure = err.Error()
	}
	c.keep(clusterImageKey(image, platform), entry)
	return summary, err
}

func (c *clusterImages) read(ctx context.Context, image checks.RunningImage, platform string) (scan.ImageSummary, error) {
	reference := image.Image
	if image.Digest != "" {
		reference += "@" + image.Digest
	}
	ref, err := images.ParseReference(reference)
	if err != nil {
		return scan.ImageSummary{}, err
	}
	client, err := c.server.registryClient(ctx, ref.Registry)
	if err != nil {
		return scan.ImageSummary{}, err
	}
	inventory, _, err := c.server.images.read(ctx, client, ref, platform)
	if err != nil {
		return scan.ImageSummary{}, err
	}
	return scan.Summarize(scan.EvaluateImage(inventory)), nil
}

// keep saves an entry, first dropping expired ones when the cache is full,
// then the oldest.
func (c *clusterImages) keep(key string, entry clusterImageEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxClusterImageEntries {
		now := c.now()
		oldestKey, oldest := "", now
		for k, e := range c.entries {
			if now.Sub(e.at) >= clusterImageKept {
				delete(c.entries, k)
			} else if e.at.Before(oldest) {
				oldestKey, oldest = k, e.at
			}
		}
		if len(c.entries) >= maxClusterImageEntries {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = entry
}
