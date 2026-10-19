package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/containers"
	"deaconguard/internal/images"
	"deaconguard/internal/store"
)

func TestRegistryLoginsKeepTheirSecrets(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)

	for name, body := range map[string]map[string]any{
		"no registry":  {"registry": "", "username": "ci", "secret": "x"},
		"a path":       {"registry": "ghcr.io/acme", "username": "ci", "secret": "x"},
		"no username":  {"registry": "ghcr.io", "username": " ", "secret": "x"},
		"no secret":    {"registry": "ghcr.io", "username": "ci", "secret": ""},
		"extra fields": {"registry": "ghcr.io", "username": "ci", "secret": "x", "id": "nope"},
	} {
		if refused := do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", body: body, cookie: cookie}); refused.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, refused.Code, refused.Body.String())
		}
	}
	created := do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", cookie: cookie,
		body: map[string]any{"registry": "docker.io", "username": "ci", "secret": "first-token"}})
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "first-token") {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	login := decode[store.RegistryLogin](t, created)
	if login.Registry != "registry-1.docker.io" {
		t.Fatalf("Docker Hub saved as %q", login.Registry)
	}
	if again := do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", cookie: cookie,
		body: map[string]any{"registry": "registry-1.docker.io", "username": "x", "secret": "y"}}); again.Code != http.StatusConflict {
		t.Fatalf("a second login for the same registry: %d", again.Code)
	}

	// An edit without a secret keeps the saved one.
	edited := do(t, s, call{method: http.MethodPatch, path: "/api/registry-logins/" + login.ID, cookie: cookie,
		body: map[string]any{"registry": "docker.io", "username": "robot", "secret": ""}})
	if edited.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", edited.Code, edited.Body.String())
	}
	if credentials, found := credentialsFor(t, s, "registry-1.docker.io"); !found || credentials.Username != "robot" || credentials.Password != "first-token" {
		t.Fatalf("credentials after edit = %+v, %v", credentials, found)
	}
	if _, found := credentialsFor(t, s, "ghcr.io"); found {
		t.Fatal("a login was given to another registry")
	}
	// The saved secret is never sent to a registry the login didn't name.
	if moved := do(t, s, call{method: http.MethodPatch, path: "/api/registry-logins/" + login.ID, cookie: cookie,
		body: map[string]any{"registry": "evil.example", "username": "robot", "secret": ""}}); moved.Code != http.StatusBadRequest {
		t.Fatalf("moving a login without its secret: %d", moved.Code)
	}
	list := do(t, s, call{method: http.MethodGet, path: "/api/registry-logins", cookie: cookie})
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "first-token") || !strings.Contains(list.Body.String(), "robot") {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	if removed := do(t, s, call{method: http.MethodDelete, path: "/api/registry-logins/" + login.ID, cookie: cookie}); removed.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", removed.Code)
	}
	if _, found := credentialsFor(t, s, "registry-1.docker.io"); found {
		t.Fatal("the deleted login is still used")
	}
}

func TestImagesAreScannedFromTheirRegistry(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	var asked []string
	s.images.read = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
		asked = append(asked, ref.String()+" "+platform)
		if ref.Repository == "acme/private" {
			return containers.Inventory{}, images.Resolved{}, fmt.Errorf("%s: %w", ref, images.ErrUnauthorized)
		}
		inventory := containers.Inventory{Container: containers.Container{Name: ref.String(), Image: ref.String(), Runtime: "registry"},
			Notes: []string{"No package database was found in the image."}}
		return inventory, images.Resolved{Reference: ref, Digest: "sha256:" + strings.Repeat("a", 64), Platform: platform}, nil
	}

	for name, body := range map[string]map[string]any{
		"bad reference": {"reference": "../etc", "platform": "linux/amd64"},
		"bad platform":  {"reference": "nginx", "platform": "windows/amd64"},
		"unknown field": {"reference": "nginx", "schedule": "daily"},
	} {
		if refused := do(t, s, call{method: http.MethodPost, path: "/api/images", body: body, cookie: cookie}); refused.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, refused.Code, refused.Body.String())
		}
	}
	added := do(t, s, call{method: http.MethodPost, path: "/api/images", cookie: cookie, body: map[string]any{"reference": "nginx:1.27"}})
	image := decode[store.Image](t, added)
	if added.Code != http.StatusCreated || image.Reference != "nginx:1.27" || image.Platform != "linux/amd64" ||
		image.Latest == nil || image.Latest.Status != store.ScanQueued {
		t.Fatalf("add: %d %s", added.Code, added.Body.String())
	}
	if again := do(t, s, call{method: http.MethodPost, path: "/api/images", cookie: cookie,
		body: map[string]any{"reference": "docker.io/library/nginx:1.27", "platform": "linux/amd64"}}); again.Code != http.StatusConflict {
		t.Fatalf("the same image twice: %d", again.Code)
	}
	// Adding queued a scan; another waits for it to finish.
	if busy := do(t, s, call{method: http.MethodPost, path: "/api/images/" + image.ID + "/scans", cookie: cookie}); busy.Code != http.StatusConflict {
		t.Fatalf("a second scan while one is queued: %d", busy.Code)
	}
	s.runQueuedImageScans(context.Background())
	if len(asked) != 1 || asked[0] != "nginx:1.27 linux/amd64" {
		t.Fatalf("read %v", asked)
	}

	detail := do(t, s, call{method: http.MethodGet, path: "/api/images/" + image.ID, cookie: cookie})
	var view struct {
		Image store.Image       `json:"image"`
		Scans []store.ImageScan `json:"scans"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &view); err != nil || len(view.Scans) != 1 {
		t.Fatalf("detail: %d %s", detail.Code, detail.Body.String())
	}
	latest := view.Image.Latest
	if latest == nil || latest.Status != store.ScanSucceeded || latest.Digest != "sha256:"+strings.Repeat("a", 64) || latest.Result != nil {
		t.Fatalf("latest scan = %+v", latest)
	}
	full := decode[store.ImageScan](t, do(t, s, call{method: http.MethodGet, path: "/api/image-scans/" + latest.ID, cookie: cookie}))
	var result checks.ContainerResult
	if err := json.Unmarshal(full.Result, &result); err != nil || result.Image != "nginx:1.27" || len(result.Notes) == 0 {
		t.Fatalf("result = %s (%v)", full.Result, err)
	}

	// A registry that refuses access fails the scan with a message saying what to do.
	private := decode[store.Image](t, do(t, s, call{method: http.MethodPost, path: "/api/images", cookie: cookie,
		body: map[string]any{"reference": "ghcr.io/acme/private:1", "platform": "linux/arm64"}}))
	s.runQueuedImageScans(context.Background())
	failed, _ := store.GetImage(private.ID)
	if failed.Latest == nil || failed.Latest.Status != store.ScanFailed || !strings.Contains(failed.Latest.Error, "add a login") {
		t.Fatalf("scan of a private image = %+v", failed.Latest)
	}

	// Only the newest scans are kept.
	for range keptImageScansForTest + 3 {
		do(t, s, call{method: http.MethodPost, path: "/api/images/" + image.ID + "/scans", cookie: cookie})
		s.runQueuedImageScans(context.Background())
	}
	if scans, _ := store.ImageScans(image.ID); len(scans) != keptImageScansForTest {
		t.Fatalf("%d scans kept", len(scans))
	}

	if removed := do(t, s, call{method: http.MethodDelete, path: "/api/images/" + image.ID, cookie: cookie}); removed.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", removed.Code)
	}
	if gone := do(t, s, call{method: http.MethodGet, path: "/api/image-scans/" + latest.ID, cookie: cookie}); gone.Code != http.StatusNotFound {
		t.Fatalf("a deleted image's scan: %d", gone.Code)
	}
}

func TestInterruptedImageScansFail(t *testing.T) {
	newNetworkTestServer(t)
	image, err := store.AddImage("alpine:3.22", "linux/amd64", false, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.QueueImageScan(image.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.NextImageScan(); !found || err != nil {
		t.Fatalf("next scan: %v %v", found, err)
	}
	if err := store.InterruptImageScans(); err != nil {
		t.Fatal(err)
	}
	image, _ = store.GetImage(image.ID)
	if image.Latest.Status != store.ScanFailed || !strings.Contains(image.Latest.Error, "server stopped") {
		t.Fatalf("interrupted scan = %+v", image.Latest)
	}
}

// credentialsFor is the login the server gives a registry's image reader.
func credentialsFor(t *testing.T, s *Server, registry string) (images.Credentials, bool) {
	t.Helper()
	client, err := s.registryClient(context.Background(), registry)
	if err != nil {
		t.Fatal(err)
	}
	return client.Credentials(registry)
}

func TestECRLoginsAreExchangedForTokens(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	const registry = "123456789012.dkr.ecr.eu-north-1.amazonaws.com"
	calls := 0
	aws := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=AKIDGOOD/") {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": "UnrecognizedClientException", "message": "invalid token"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"authorizationData": []map[string]any{{
			"authorizationToken": base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("AWS:token-%d", calls))),
			"expiresAt":          float64(time.Now().Add(12 * time.Hour).Unix()),
		}}})
	}))
	defer aws.Close()
	s.images.http, s.images.ecrEndpoint = aws.Client(), aws.URL

	if wrongHost := do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", cookie: cookie,
		body: map[string]any{"registry": "ghcr.io", "kind": "ecr", "username": "AKIDGOOD", "secret": "s"}}); wrongHost.Code != http.StatusBadRequest {
		t.Fatalf("an AWS key for GHCR: %d", wrongHost.Code)
	}
	created := do(t, s, call{method: http.MethodPost, path: "/api/registry-logins", cookie: cookie,
		body: map[string]any{"registry": registry, "kind": "ecr", "username": "AKIDGOOD", "secret": "s"}})
	login := decode[store.RegistryLogin](t, created)
	if created.Code != http.StatusCreated || login.Kind != store.LoginECR {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	if credentials, found := credentialsFor(t, s, registry); !found || credentials.Username != "AWS" || credentials.Password != "token-1" {
		t.Fatalf("credentials = %+v, %v", credentials, found)
	}
	// The token is reused until it nears its expiry.
	if credentials, _ := credentialsFor(t, s, registry); credentials.Password != "token-1" || calls != 1 {
		t.Fatalf("second use: %+v after %d calls", credentials, calls)
	}
	// A changed key gets a new token; a wrong one fails with AWS's reason.
	do(t, s, call{method: http.MethodPatch, path: "/api/registry-logins/" + login.ID, cookie: cookie,
		body: map[string]any{"registry": registry, "kind": "ecr", "username": "AKIDBAD", "secret": "t"}})
	if _, err := s.registryClient(context.Background(), registry); err == nil || !strings.Contains(err.Error(), "UnrecognizedClientException") {
		t.Fatalf("a wrong key: %v", err)
	}
}

func TestWatchedImagesAreScannedWhenTheTagMoves(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	digest, failure := "sha256:"+strings.Repeat("1", 64), error(nil)
	checks := 0
	s.images.tagDigest = func(ctx context.Context, client *images.Client, ref images.Reference) (string, error) {
		checks++
		return digest, failure
	}
	s.images.read = func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
		return containers.Inventory{Container: containers.Container{Name: ref.String(), Image: ref.String()}},
			images.Resolved{Reference: ref, Digest: "sha256:" + strings.Repeat("9", 64), TagDigest: digest, Platform: platform}, nil
	}
	watched := decode[store.Image](t, do(t, s, call{method: http.MethodPost, path: "/api/images", cookie: cookie, body: map[string]any{"reference": "nginx:1.27"}}))
	unwatched := decode[store.Image](t, do(t, s, call{method: http.MethodPost, path: "/api/images", cookie: cookie,
		body: map[string]any{"reference": "redis:7", "watch": false}}))
	if !watched.Watch || unwatched.Watch {
		t.Fatalf("watch: %v, %v", watched.Watch, unwatched.Watch)
	}
	s.runQueuedImageScans(context.Background())
	if image, _ := store.GetImage(watched.ID); image.TagDigest != digest {
		t.Fatalf("the scan didn't record the tag's digest: %+v", image)
	}
	scans := func(id string) int {
		list, _ := store.ImageScans(id)
		return len(list)
	}

	now := time.Now()
	s.checkWatchedImages(context.Background(), now)
	if checks != 1 || scans(watched.ID) != 1 {
		t.Fatalf("an unchanged tag: %d checks, %d scans", checks, scans(watched.ID))
	}
	// Not due again for 15 minutes; the unwatched image is never checked.
	digest = "sha256:" + strings.Repeat("2", 64)
	s.checkWatchedImages(context.Background(), now.Add(time.Minute))
	if checks != 1 {
		t.Fatalf("checked again after a minute: %d", checks)
	}
	s.checkWatchedImages(context.Background(), now.Add(16*time.Minute))
	latest, _ := store.GetImage(watched.ID)
	if checks != 2 || latest.Latest.Status != store.ScanQueued || latest.Latest.StartedBy != "watch: new build pushed" {
		t.Fatalf("after a push: %d checks, %+v", checks, latest.Latest)
	}
	s.runQueuedImageScans(context.Background())

	// A failed check is shown, logged once, and queues nothing.
	failure = errors.New("registry-1.docker.io: the registry is rate-limiting requests")
	s.checkWatchedImages(context.Background(), now.Add(32*time.Minute))
	if image, _ := store.GetImage(watched.ID); !strings.Contains(image.WatchError, "rate-limiting") || image.TagDigest != digest || scans(watched.ID) != 2 {
		t.Fatalf("after a failed check: %+v, %d scans", image, scans(watched.ID))
	}
	// A day after the last scan, the image is scanned again for new advisories.
	failure = nil
	s.checkWatchedImages(context.Background(), now.Add(25*time.Hour))
	if image, _ := store.GetImage(watched.ID); image.WatchError != "" || image.Latest.StartedBy != "watch: daily rescan" {
		t.Fatalf("a day later: %+v", image)
	}
	if scans(unwatched.ID) != 1 {
		t.Fatalf("the unwatched image was scanned %d times", scans(unwatched.ID))
	}

	// Watching can be turned off.
	off := do(t, s, call{method: http.MethodPatch, path: "/api/images/" + watched.ID, cookie: cookie, body: map[string]any{"watch": false}})
	if off.Code != http.StatusOK || decode[store.Image](t, off).Watch {
		t.Fatalf("turn off: %d %s", off.Code, off.Body.String())
	}
	if bad := do(t, s, call{method: http.MethodPatch, path: "/api/images/" + watched.ID, cookie: cookie, body: map[string]any{}}); bad.Code != http.StatusBadRequest {
		t.Fatalf("an empty change: %d", bad.Code)
	}
}

func TestNewImageVulnerabilitiesAreNotified(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	h := newHook(t)
	channel := addChannel(t, s, cookie, map[string]any{"name": "images", "kind": "webhook", "config": map[string]any{"url": h.server.URL},
		"events": []string{"exploited", "critical", "scan_failed"}})
	image, _ := store.AddImage("nginx:1.27", "linux/amd64", false, "test")
	finish := func(findings ...checks.Finding) string {
		record, err := store.QueueImageScan(image.ID, "test")
		if err != nil {
			t.Fatal(err)
		}
		result := checks.ContainerResult{Findings: findings}
		record.Result, _ = json.Marshal(result)
		if err := store.FinishImageScan(record, ""); err != nil {
			t.Fatal(err)
		}
		s.newImageVulnerabilities(image, record.ID, result)
		return record.ID
	}
	kev := checks.Finding{Rule: "CVE-2023-44487", Severity: "HIGH", Detail: "Fixed in 1.2: update the image. Known to be exploited (CISA KEV)."}
	critical := checks.Finding{Rule: "CVE-2024-1", Severity: "CRITICAL", Detail: "Fixed in 2.0: update the image."}
	finish(kev)
	finish(kev, critical)
	finish(kev, critical)
	deliveries, err := store.Deliveries(channel.ID, 10)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries: %+v, %v", deliveries, err)
	}
	titles := deliveries[0].Title + " | " + deliveries[1].Title
	if !strings.Contains(titles, "Image nginx:1.27: 1 new vulnerability known to be exploited") ||
		!strings.Contains(titles, "Image nginx:1.27: 1 new critical vulnerability with a fix") {
		t.Fatalf("titles: %s", titles)
	}
}

// keptImageScansForTest matches store.keptImageScans.
const keptImageScansForTest = 20
