package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

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
	if credentials, found := registryCredentials("registry-1.docker.io"); !found || credentials.Username != "robot" || credentials.Password != "first-token" {
		t.Fatalf("credentials after edit = %+v, %v", credentials, found)
	}
	if _, found := registryCredentials("ghcr.io"); found {
		t.Fatal("a login was given to another registry")
	}
	list := do(t, s, call{method: http.MethodGet, path: "/api/registry-logins", cookie: cookie})
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "first-token") || !strings.Contains(list.Body.String(), "robot") {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	if removed := do(t, s, call{method: http.MethodDelete, path: "/api/registry-logins/" + login.ID, cookie: cookie}); removed.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", removed.Code)
	}
	if _, found := registryCredentials("registry-1.docker.io"); found {
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
	image, err := store.AddImage("alpine:3.22", "linux/amd64", "test")
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

// keptImageScansForTest matches store.keptImageScans.
const keptImageScansForTest = 20
