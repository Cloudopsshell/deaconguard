package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/images"
	"deaconguard/internal/scan"
)

// The images clusters run are checked on the server (scan.EvaluateClusterImages),
// and each result kept in memory: a build for a day, so new advisories are
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
}

func newClusterImages(s *Server) *clusterImages {
	return &clusterImages{server: s, now: time.Now, entries: map[string]clusterImageEntry{}}
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
	c.mu.Lock()
	defer c.mu.Unlock()
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
