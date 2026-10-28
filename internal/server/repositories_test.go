package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/containers"
	"deaconguard/internal/images"
	"deaconguard/internal/store"
)

func TestRepositoryWatchesScanNewPushes(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tags := []images.TagInfo{
		{Tag: "v1", Digest: "sha256:01", PushedAt: base},
		{Tag: "v2", Digest: "sha256:02", PushedAt: base.Add(time.Hour)},
		{Tag: "v3", Digest: "sha256:03", PushedAt: base.Add(2 * time.Hour)},
		{Tag: "main-abc", Digest: "sha256:0a", PushedAt: base.Add(3 * time.Hour)},
	}
	s.images.listTags = func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
		return append([]images.TagInfo(nil), tags...), nil
	}
	s.images.read = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
		digest := ""
		for _, tag := range tags {
			if tag.Tag == ref.Tag {
				digest = tag.Digest
			}
		}
		return containers.Inventory{Container: containers.Container{Name: ref.String(), Image: ref.String()}},
			images.Resolved{Reference: ref, Digest: digest, TagDigest: digest, Platform: platform}, nil
	}
	if bad := do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie,
		body: map[string]any{"registry": "ghcr.io", "repository": "acme/app", "tag_pattern": "("}}); bad.Code != http.StatusBadRequest {
		t.Fatalf("a broken pattern: %d", bad.Code)
	}
	created := do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie,
		body: map[string]any{"registry": "ghcr.io", "repository": "acme/app", "tag_pattern": `^v\d+$`, "keep": 2}})
	watch := decode[store.RepositoryWatch](t, created)
	if created.Code != http.StatusCreated || watch.Keep != 2 || watch.Platform != "linux/amd64" {
		t.Fatalf("add: %d %s", created.Code, created.Body.String())
	}
	byReference := func() map[string]store.Image {
		list, _ := store.Images()
		found := map[string]store.Image{}
		for _, image := range list {
			found[image.Reference] = image
		}
		return found
	}
	now := time.Now()
	s.checkRepositoryWatches(context.Background(), now)
	found := byReference()
	if len(found) != 2 || found["ghcr.io/acme/app:v3"].ID == "" || found["ghcr.io/acme/app:v2"].ID == "" {
		t.Fatalf("the first check should add the newest 2 matching tags: %v", found)
	}
	if latest := found["ghcr.io/acme/app:v3"].Latest; latest == nil || latest.StartedBy != "watch: repository added" {
		t.Fatalf("v3 wasn't queued: %+v", latest)
	}
	s.runQueuedImageScans(context.Background())

	// Nothing new: nothing is queued, and it isn't due again for 15 minutes.
	s.checkRepositoryWatches(context.Background(), now.Add(16*time.Minute))
	if latest := byReference()["ghcr.io/acme/app:v3"].Latest; latest.Status != store.ScanSucceeded {
		t.Fatalf("an unchanged repository queued a scan: %+v", latest)
	}

	// A new matching push is scanned, and the oldest kept tag stops being watched.
	tags = append(tags, images.TagInfo{Tag: "v4", Digest: "sha256:04", PushedAt: base.Add(4 * time.Hour)})
	s.checkRepositoryWatches(context.Background(), now.Add(32*time.Minute))
	found = byReference()
	if latest := found["ghcr.io/acme/app:v4"].Latest; latest == nil || latest.StartedBy != "watch: new push of v4" {
		t.Fatalf("v4: %+v", found["ghcr.io/acme/app:v4"])
	}
	if found["ghcr.io/acme/app:v2"].Watch || !found["ghcr.io/acme/app:v3"].Watch {
		t.Fatalf("keep 2: v2 watched %v, v3 watched %v", found["ghcr.io/acme/app:v2"].Watch, found["ghcr.io/acme/app:v3"].Watch)
	}
	s.runQueuedImageScans(context.Background())

	// A tag pushed again with a new image is scanned again.
	tags[2] = images.TagInfo{Tag: "v3", Digest: "sha256:33", PushedAt: base.Add(5 * time.Hour)}
	s.checkRepositoryWatches(context.Background(), now.Add(48*time.Minute))
	if latest := byReference()["ghcr.io/acme/app:v3"].Latest; latest.Status != store.ScanQueued || latest.StartedBy != "watch: new push of v3" {
		t.Fatalf("a re-pushed v3: %+v", latest)
	}
	s.runQueuedImageScans(context.Background())

	// A failed listing is shown on the watch.
	s.images.listTags = func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
		return nil, fmt.Errorf("ghcr.io: %w", images.ErrUnauthorized)
	}
	s.checkRepositoryWatches(context.Background(), now.Add(64*time.Minute))
	if got, _ := store.GetRepositoryWatch(watch.ID); !strings.Contains(got.WatchError, "refused access") || got.Images != 3 {
		t.Fatalf("after a failed check: %+v", got)
	}

	// Changing the pattern starts afresh; deleting keeps the images, unwatched.
	changed := do(t, s, call{method: http.MethodPatch, path: "/api/repository-watches/" + watch.ID, cookie: cookie, body: map[string]any{"tag_pattern": "^main-", "keep": 1}})
	if changed.Code != http.StatusOK || decode[store.RepositoryWatch](t, changed).TagPattern != "^main-" {
		t.Fatalf("change: %d %s", changed.Code, changed.Body.String())
	}
	if known, _ := store.RepositoryTags(watch.ID); len(known) != 0 {
		t.Fatalf("the seen tags were kept: %v", known)
	}
	if gone := do(t, s, call{method: http.MethodDelete, path: "/api/repository-watches/" + watch.ID, cookie: cookie}); gone.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", gone.Code)
	}
	for reference, image := range byReference() {
		if image.Watch || image.RepositoryWatchID != "" {
			t.Errorf("%s still watched after the watch was deleted", reference)
		}
	}
}

func TestRepositoryWatchWithoutPushTimes(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	names := []string{"1.9.0", "1.10.0", "1.2.0"}
	s.images.listTags = func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
		var tags []images.TagInfo
		for _, name := range names {
			tags = append(tags, images.TagInfo{Tag: name})
		}
		return tags, nil
	}
	asked := 0
	s.images.tagDigest = func(ctx context.Context, client *images.Client, ref images.Reference) (string, error) {
		asked++
		return "sha256:" + ref.Tag, nil
	}
	decode[store.RepositoryWatch](t, do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie,
		body: map[string]any{"registry": "registry.example.com", "repository": "team/db", "keep": 1}}))
	now := time.Now()
	s.checkRepositoryWatches(context.Background(), now)
	list, _ := store.Images()
	if len(list) != 1 || list[0].Reference != "registry.example.com/team/db:1.10.0" || asked != 1 {
		t.Fatalf("natural order on the first check, digests only for kept tags: %d asked, %+v", asked, list)
	}
	// A tag that appears later counts as the newest, whatever its name.
	names = append(names, "0.1-hotfix")
	s.checkRepositoryWatches(context.Background(), now.Add(16*time.Minute))
	list, _ = store.Images()
	if len(list) != 2 || !strings.Contains(list[0].Reference+list[1].Reference, "0.1-hotfix") {
		t.Fatalf("a new tag: %+v", list)
	}
}

func TestBrowsingRegistries(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	login := decode[store.RegistryLogin](t, do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", cookie: cookie,
		body: map[string]any{"registry": "ghcr.io", "username": "robot", "secret": "token"}}))
	refuse := false
	s.images.listRepositories = func(ctx context.Context, s *Server, login store.RegistryLogin) ([]string, error) {
		if refuse {
			return nil, fmt.Errorf("ghcr.io: %w", images.ErrListingRefused)
		}
		return []string{"acme/api", "acme/web"}, nil
	}
	s.images.listTags = func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
		if repository != "acme/web" {
			return nil, errors.New("unexpected repository " + repository)
		}
		return []images.TagInfo{{Tag: "v1.9"}, {Tag: "v1.10"}, {Tag: "dev"}}, nil
	}
	type listing struct {
		Repositories []string `json:"repositories"`
		Listed       bool     `json:"listed"`
		Message      string   `json:"message"`
	}
	got := decode[listing](t, do(t, s, call{method: http.MethodGet, path: "/api/registry-logins/" + login.ID + "/repositories", cookie: cookie}))
	if !got.Listed || strings.Join(got.Repositories, ",") != "acme/api,acme/web" {
		t.Fatalf("repositories: %+v", got)
	}
	refuse = true
	got = decode[listing](t, do(t, s, call{method: http.MethodGet, path: "/api/registry-logins/" + login.ID + "/repositories", cookie: cookie}))
	if got.Listed || !strings.Contains(got.Message, "Type the repository's name") {
		t.Fatalf("a refused listing: %+v", got)
	}
	type tags struct {
		Tags []struct {
			Tag       string `json:"tag"`
			Matches   bool   `json:"matches"`
			Reference string `json:"reference"`
		} `json:"tags"`
		Matched int `json:"matched"`
	}
	answer := do(t, s, call{method: http.MethodGet, path: "/api/registry-logins/" + login.ID + "/tags?repository=acme/web&pattern=%5Ev", cookie: cookie})
	view := decode[tags](t, answer)
	if answer.Code != http.StatusOK || view.Matched != 2 || view.Tags[0].Tag != "v1.10" || !view.Tags[0].Matches || view.Tags[2].Matches || view.Tags[0].Reference != "ghcr.io/acme/web:v1.10" {
		t.Fatalf("tags: %d %+v", answer.Code, view)
	}
	if bad := do(t, s, call{method: http.MethodGet, path: "/api/registry-logins/" + login.ID + "/tags?repository=acme/web&pattern=(", cookie: cookie}); bad.Code != http.StatusBadRequest {
		t.Fatalf("a broken pattern: %d", bad.Code)
	}
}
