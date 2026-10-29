package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
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
	// This registry's images don't say when they were built.
	s.images.created = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (time.Time, error) {
		return time.Time{}, errors.New("no config")
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

func TestRepositoryWatchByBuildTime(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	// Commit tags: their names say nothing of their order.
	names := []string{"main-9f2c", "main-0b7a", "main-c41d"}
	built := map[string]time.Time{}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for index, name := range names {
		built[name] = base.Add(time.Duration(index) * time.Hour)
	}
	s.images.listTags = func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
		var tags []images.TagInfo
		for _, name := range names {
			tags = append(tags, images.TagInfo{Tag: name})
		}
		return tags, nil
	}
	s.images.tagDigest = func(ctx context.Context, client *images.Client, ref images.Reference) (string, error) {
		return "sha256:" + ref.Tag, nil
	}
	var reads []string
	var mu sync.Mutex
	s.images.created = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (time.Time, error) {
		mu.Lock()
		defer mu.Unlock()
		reads = append(reads, ref.Registry+" "+ref.Tag+" "+platform)
		return built[ref.Tag], nil
	}
	login := decode[store.RegistryLogin](t, do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", cookie: cookie,
		body: map[string]any{"registry": "registry.example.com", "username": "robot", "secret": "token"}}))

	// The preview for a platform orders the matching tags by build time, as
	// the first check will.
	type tagList struct {
		Tags []images.TagInfo `json:"tags"`
	}
	preview := decode[tagList](t, do(t, s, call{method: http.MethodGet, cookie: cookie,
		path: "/api/registry-logins/" + login.ID + "/tags?repository=team/app&pattern=%5Emain-&platform=linux/amd64"}))
	if len(preview.Tags) != 3 || preview.Tags[0].Tag != "main-c41d" || preview.Tags[2].Tag != "main-9f2c" || !preview.Tags[0].Created.Equal(built["main-c41d"]) {
		t.Fatalf("preview: %+v", preview.Tags)
	}
	// Browsing without a platform reads nothing.
	reads = nil
	decode[tagList](t, do(t, s, call{method: http.MethodGet, cookie: cookie, path: "/api/registry-logins/" + login.ID + "/tags?repository=team/app"}))
	if len(reads) != 0 {
		t.Fatalf("plain browsing read build times: %v", reads)
	}

	decode[store.RepositoryWatch](t, do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie,
		body: map[string]any{"registry": "registry.example.com", "repository": "team/app", "tag_pattern": "^main-", "platform": "linux/amd64", "keep": 1}}))
	now := time.Now()
	s.checkRepositoryWatches(context.Background(), now)
	list, _ := store.Images()
	if len(list) != 1 || list[0].Reference != "registry.example.com/team/app:main-c41d" {
		t.Fatalf("the newest build on the first check: %+v", list)
	}
	if len(reads) != 0 {
		t.Fatalf("the preview's build times weren't reused: %v", reads)
	}
	// Two pushes seen together: the later build is the newer push. The first
	// check's build times are kept, so the old tags aren't read again.
	names = append(names, "main-77aa", "main-e5e0")
	built["main-77aa"], built["main-e5e0"] = base.Add(9*time.Hour), base.Add(8*time.Hour)
	s.checkRepositoryWatches(context.Background(), now.Add(16*time.Minute))
	list, _ = store.Images()
	watched := ""
	for _, image := range list {
		if image.Watch {
			watched += image.Reference
		}
	}
	if !strings.HasSuffix(watched, ":main-77aa") || strings.Count(watched, "registry.example.com") != 1 {
		t.Fatalf("pushed together: watched %s of %+v", watched, list)
	}
	if strings.Join(reads, ",") != "registry.example.com main-77aa linux/amd64,registry.example.com main-e5e0 linux/amd64" &&
		strings.Join(reads, ",") != "registry.example.com main-e5e0 linux/amd64,registry.example.com main-77aa linux/amd64" {
		t.Fatalf("reads on the second check: %v", reads)
	}

	// Docker Hub limits reads: its tags stay in version order.
	reads = nil
	decode[store.RepositoryWatch](t, do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie,
		body: map[string]any{"registry": "docker.io", "repository": "library/app", "keep": 1}}))
	s.checkRepositoryWatches(context.Background(), now.Add(32*time.Minute))
	if len(reads) != 0 {
		t.Fatalf("read build times on Docker Hub: %v", reads)
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

func TestNewPushReportsAndHistory(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	chosen, other := newHook(t), newHook(t)
	a := addChannel(t, s, cookie, map[string]any{"name": "team", "kind": "webhook", "config": map[string]any{"url": chosen.server.URL}, "events": []string{"image_report"}})
	addChannel(t, s, cookie, map[string]any{"name": "everyone", "kind": "webhook", "config": map[string]any{"url": other.server.URL}, "events": []string{"image_report"}})
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tags := []images.TagInfo{{Tag: "v0", Digest: "sha256:00", PushedAt: base.Add(-time.Hour)}, {Tag: "v1", Digest: "sha256:01", PushedAt: base}}
	s.images.listTags = func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
		return append([]images.TagInfo(nil), tags...), nil
	}
	s.images.read = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
		digest := "sha256:" + ref.Tag
		return containers.Inventory{Container: containers.Container{Name: ref.String(), Image: ref.String()}},
			images.Resolved{Reference: ref, Digest: digest, TagDigest: "sha256:0" + strings.TrimPrefix(ref.Tag, "v"), Platform: platform}, nil
	}
	for _, body := range []map[string]any{
		{"registry": "ghcr.io", "repository": "acme/app", "keep": 3, "history": 2},
		{"registry": "ghcr.io", "repository": "acme/app", "notify_level": "loud"},
		{"registry": "ghcr.io", "repository": "acme/app", "notify_channels": []string{"nope"}},
	} {
		if bad := do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie, body: body}); bad.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", body, bad.Code)
		}
	}
	created := do(t, s, call{method: http.MethodPost, path: "/api/repository-watches", cookie: cookie,
		body: map[string]any{"registry": "ghcr.io", "repository": "acme/app", "keep": 2, "history": 2, "notify_channels": []string{a.ID}}})
	watch := decode[store.RepositoryWatch](t, created)
	if created.Code != http.StatusCreated || watch.History != 2 || watch.NotifyLevel != "any" || len(watch.NotifyChannels) != 1 {
		t.Fatalf("add: %d %s", created.Code, created.Body.String())
	}
	now := time.Now()
	check := func(push string) {
		t.Helper()
		if push != "" {
			tags = append(tags, images.TagInfo{Tag: push, Digest: "sha256:0" + strings.TrimPrefix(push, "v"), PushedAt: base.Add(time.Duration(len(tags)) * time.Hour)})
		}
		now = now.Add(16 * time.Minute)
		s.checkRepositoryWatches(context.Background(), now)
		s.runQueuedImageScans(context.Background())
		s.deliverDue(context.Background(), time.Now())
	}

	// The first check isn't a new push: no report.
	check("")
	if len(chosen.events()) != 0 {
		t.Fatalf("the first check sent a report: %v", chosen.events())
	}
	// A new push is reported to the chosen channel only.
	check("v2")
	if events := chosen.events(); len(events) != 1 || events[0] != "image_report" || len(other.events()) != 0 {
		t.Fatalf("reports: chosen %v, other %v", events, other.events())
	}
	chosen.mu.Lock()
	report := chosen.messages[0]
	chosen.mu.Unlock()
	data, _ := report["data"].(map[string]any)
	if report["title"] != "New push of ghcr.io/acme/app:v2: no vulnerabilities" || data["previous"] != "ghcr.io/acme/app:v1" || data["tag"] != "v2" {
		t.Fatalf("report: %v", report)
	}

	// History 2: a new image removes the oldest, with its scans; v0 and v1
	// were added by the same check, oldest first.
	references := func() string {
		list, _ := store.Images()
		names := []string{}
		for _, image := range list {
			names = append(names, strings.TrimPrefix(image.Reference, "ghcr.io/acme/app:"))
		}
		slices.Sort(names)
		return strings.Join(names, ",")
	}
	if got := references(); got != "v1,v2" {
		t.Fatalf("history 2 after v2 kept %s", got)
	}
	check("v3")
	if got := references(); got != "v2,v3" {
		t.Fatalf("history 2 after v3 kept %s", got)
	}

	// Only critical pushes: a clean one isn't reported.
	if patched := do(t, s, call{method: http.MethodPatch, path: "/api/repository-watches/" + watch.ID, cookie: cookie,
		body: map[string]any{"notify_level": "critical"}}); patched.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", patched.Code, patched.Body.String())
	}
	if after, _ := store.GetRepositoryWatch(watch.ID); after.CheckedAt == "" {
		t.Fatal("changing the report setting started the watch afresh")
	}
	check("v4")
	if len(chosen.events()) != 2 {
		t.Fatalf("reports after limiting to critical: %v", chosen.events())
	}

	detail := do(t, s, call{method: http.MethodGet, path: "/api/repository-watches/" + watch.ID, cookie: cookie})
	builds := decode[repositoryWatchDetail](t, detail).Builds
	if detail.Code != http.StatusOK || len(builds) != 2 || builds[0].Reference != "ghcr.io/acme/app:v4" || !builds[0].Watched || !builds[1].Watched {
		t.Fatalf("builds: %d %s", detail.Code, detail.Body.String())
	}
}

func TestReportLevels(t *testing.T) {
	high := store.ImageScan{Severity: store.SeverityCounts{High: 1}}
	for level, want := range map[string]bool{"off": false, "any": true, "low": true, "medium": true, "high": true, "critical": false, "exploited": false} {
		if reports(level, high) != want {
			t.Errorf("%s with a high vulnerability: want %v", level, want)
		}
	}
	if !reports("exploited", store.ImageScan{Exploited: 1}) || reports("low", store.ImageScan{Severity: store.SeverityCounts{Unknown: 3}}) {
		t.Error("exploited and unknown")
	}
}
