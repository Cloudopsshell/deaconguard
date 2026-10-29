package images

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type tarFile struct {
	name, body, link string
}

func layer(t *testing.T, files ...tarFile) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		header := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if f.link != "" {
			header = &tar.Header{Name: f.name, Typeflag: tar.TypeSymlink, Linkname: f.link}
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(f.body))
	}
	tw.Close()
	gz.Close()
	return raw.Bytes()
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fakeRegistry serves one two-platform image behind a bearer-token login.
type fakeRegistry struct {
	blobs     map[string][]byte
	manifests map[string][]byte
	types     map[string]string
	token     string
	logins    int
	// heads counts HEAD requests; noDigest leaves out Docker-Content-Digest.
	heads    int
	noDigest bool
}

func newFakeRegistry(t *testing.T, layers [][]byte) (*fakeRegistry, *httptest.Server) {
	r := &fakeRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, types: map[string]string{}, token: "secret-token"}
	var descriptors []map[string]any
	for _, l := range layers {
		r.blobs[digestOf(l)] = l
		descriptors = append(descriptors, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digestOf(l), "size": len(l)})
	}
	amd64, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "config": map[string]any{"digest": "sha256:" + strings.Repeat("0", 64)}, "layers": descriptors})
	arm64, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest, "layers": descriptors[:1]})
	r.manifests[digestOf(amd64)], r.types[digestOf(amd64)] = amd64, mediaOCIManifest
	r.manifests[digestOf(arm64)], r.types[digestOf(arm64)] = arm64, mediaOCIManifest
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex, "manifests": []map[string]any{
		{"mediaType": mediaOCIManifest, "digest": digestOf(arm64), "platform": map[string]string{"os": "linux", "architecture": "arm64", "variant": "v8"}},
		{"mediaType": mediaOCIManifest, "digest": digestOf(amd64), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		{"mediaType": mediaOCIManifest, "digest": "sha256:" + strings.Repeat("a", 64), "platform": map[string]string{"os": "unknown", "architecture": "unknown"}},
	}})
	r.manifests["1.0"], r.types["1.0"] = index, mediaOCIIndex
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/token" {
			user, pass, _ := req.BasicAuth()
			if user != "robot" || pass != "pw" || req.URL.Query().Get("scope") != "repository:acme/shop:pull" {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			r.logins++
			json.NewEncoder(w).Encode(map[string]string{"token": r.token})
			return
		}
		if req.Header.Get("Authorization") != "Bearer "+r.token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="fake",scope="repository:acme/shop:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if ref, ok := strings.CutPrefix(req.URL.Path, "/v2/acme/shop/manifests/"); ok {
			if body, found := r.manifests[ref]; found {
				if req.Method == http.MethodHead {
					r.heads++
				}
				w.Header().Set("Content-Type", r.types[ref])
				if !r.noDigest {
					w.Header().Set("Docker-Content-Digest", digestOf(body))
				}
				w.Write(body)
				return
			}
		}
		if digest, ok := strings.CutPrefix(req.URL.Path, "/v2/acme/shop/blobs/"); ok {
			if body, found := r.blobs[digest]; found {
				w.Write(body)
				return
			}
		}
		http.NotFound(w, req)
	}))
	return r, server
}

func testClient(server *httptest.Server, user, pass string) (*Client, Reference) {
	client := &Client{HTTP: server.Client(), Scheme: "https", Credentials: func(string) (Credentials, bool) {
		return Credentials{Username: user, Password: pass}, user != ""
	}}
	return client, Reference{Registry: strings.TrimPrefix(server.URL, "https://"), Repository: "acme/shop", Tag: "1.0"}
}

func TestReadImage(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	base := layer(t,
		tarFile{name: "usr/lib/os-release", body: "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"},
		tarFile{name: "etc/os-release", link: "../usr/lib/os-release"},
		tarFile{name: "var/lib/dpkg/status", body: "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\nArchitecture: amd64\n\n"},
		tarFile{name: "app/old/package-lock.json", body: `{"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}`},
		tarFile{name: "usr/share/doc/README", body: "not read"},
	)
	app := layer(t,
		tarFile{name: "app/old/.wh.package-lock.json"},
		tarFile{name: "app/package-lock.json", body: `{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`},
	)
	registry, server := newFakeRegistry(t, [][]byte{base, app})
	defer server.Close()
	client, ref := testClient(server, "robot", "pw")

	inventory, resolved, err := Read(context.Background(), client, ref, "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Platform != "linux/amd64" || len(resolved.Layers) != 2 || !strings.HasPrefix(resolved.Digest, "sha256:") {
		t.Errorf("resolved = %+v", resolved)
	}
	if !strings.Contains(inventory.OSRelease, "ID=debian") || !strings.Contains(inventory.DPKGStatus, "Package: openssl") {
		t.Errorf("os-release through its link = %q, dpkg = %q", inventory.OSRelease, inventory.DPKGStatus)
	}
	if inventory.Libraries == nil || len(inventory.Libraries.Libraries) != 1 || inventory.Libraries.Libraries[0].Name != "lodash" {
		t.Errorf("libraries = %+v; the whiteout must delete left-pad's lock file", inventory.Libraries)
	}
	if inventory.Runtime != "registry" || inventory.ImageID != resolved.Digest {
		t.Errorf("container = %+v", inventory.Container)
	}
	if registry.logins != 1 {
		t.Errorf("logins = %d; the token must be reused", registry.logins)
	}

	// The second read takes the layers from the cache: no blob requests.
	delete(registry.blobs, digestOf(base))
	delete(registry.blobs, digestOf(app))
	if _, _, err := Read(context.Background(), client, ref, "linux/amd64", nil); err != nil {
		t.Errorf("cached read: %v", err)
	}

	if _, _, err := Read(context.Background(), client, ref, "linux/s390x", nil); err == nil || !strings.Contains(err.Error(), "linux/arm64/v8, linux/amd64") {
		t.Errorf("unknown platform: %v", err)
	}
}

func TestTagDigestFollowsTheTag(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	registry, server := newFakeRegistry(t, [][]byte{layer(t, tarFile{name: "etc/os-release", body: "ID=alpine\n"})})
	defer server.Close()
	client, ref := testClient(server, "robot", "pw")
	_, resolved, err := Read(context.Background(), client, ref, "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.TagDigest != digestOf(registry.manifests["1.0"]) || resolved.TagDigest == resolved.Digest {
		t.Fatalf("tag digest %s, platform digest %s", resolved.TagDigest, resolved.Digest)
	}
	digest, err := client.TagDigest(context.Background(), ref)
	if err != nil || digest != resolved.TagDigest || registry.heads != 1 {
		t.Fatalf("TagDigest = %s, %v after %d HEAD requests", digest, err, registry.heads)
	}
	// The tag moves to a new build.
	registry.manifests["1.0"] = append(registry.manifests["1.0"], ' ')
	if moved, _ := client.TagDigest(context.Background(), ref); moved == digest || moved != digestOf(registry.manifests["1.0"]) {
		t.Fatalf("after the tag moved: %s", moved)
	}
	// Without Docker-Content-Digest, the manifest itself says.
	registry.noDigest = true
	if read, err := client.TagDigest(context.Background(), ref); err != nil || read != digestOf(registry.manifests["1.0"]) {
		t.Fatalf("without the header: %s, %v", read, err)
	}
	pinned := ref
	pinned.Digest = "sha256:" + strings.Repeat("b", 64)
	if same, _ := client.TagDigest(context.Background(), pinned); same != pinned.Digest {
		t.Fatalf("a pinned digest: %s", same)
	}
}

func TestLayerMustMatchItsDigest(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	good := layer(t, tarFile{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.22.1\n"})
	registry, server := newFakeRegistry(t, [][]byte{good})
	defer server.Close()
	registry.blobs[digestOf(good)] = layer(t, tarFile{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.22.2\n"})
	client, ref := testClient(server, "robot", "pw")
	if _, _, err := Read(context.Background(), client, ref, "linux/amd64", nil); err == nil || !strings.Contains(err.Error(), "doesn't match its digest") {
		t.Errorf("tampered layer: %v", err)
	}
}

func TestWrongLogin(t *testing.T) {
	_, server := newFakeRegistry(t, [][]byte{layer(t)})
	defer server.Close()
	client, ref := testClient(server, "robot", "wrong")
	if _, err := client.Resolve(context.Background(), ref, "linux/amd64"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
	anonymous, ref := testClient(server, "", "")
	if _, err := anonymous.Resolve(context.Background(), ref, "linux/amd64"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("anonymous err = %v, want ErrUnauthorized", err)
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, params := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`)
	if scheme != "Bearer" || params["realm"] != "https://auth.docker.io/token" || params["service"] != "registry.docker.io" || params["scope"] != "repository:library/nginx:pull" {
		t.Errorf("%s %v", scheme, params)
	}
}

func TestCheckLogin(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/token":
			// Logging in without a scope, as docker login does.
			user, pass, _ := req.BasicAuth()
			if user != "robot" || pass != "pw" || req.URL.Query().Get("account") != "robot" || req.URL.Query().Get("scope") != "" {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "login-token"})
		case req.URL.Path == "/v2/" && req.Header.Get("Authorization") == "Bearer login-token":
			w.WriteHeader(http.StatusOK)
		case req.URL.Path == "/v2/":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="fake"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "https://")
	check := func(user, pass string, have bool) error {
		client := &Client{HTTP: server.Client(), Scheme: "https", Credentials: func(string) (Credentials, bool) {
			return Credentials{Username: user, Password: pass}, have
		}}
		return client.CheckLogin(context.Background(), registry)
	}
	if err := check("robot", "pw", true); err != nil {
		t.Errorf("the right login: %v", err)
	}
	if err := check("robot", "wrong", true); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("a wrong password: %v, want ErrUnauthorized", err)
	}
	if err := check("", "", false); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("no login: %v, want ErrUnauthorized", err)
	}

	// A registry with Basic logins, such as ECR's, takes the login directly.
	basic := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if user, pass, ok := req.BasicAuth(); ok && user == "AWS" && pass == "token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="https://example.com/"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer basic.Close()
	for _, test := range []struct {
		pass string
		ok   bool
	}{{"token", true}, {"expired", false}} {
		client := &Client{HTTP: basic.Client(), Scheme: "https", Credentials: func(string) (Credentials, bool) {
			return Credentials{Username: "AWS", Password: test.pass}, true
		}}
		err := client.CheckLogin(context.Background(), strings.TrimPrefix(basic.URL, "https://"))
		if test.ok != (err == nil) || (!test.ok && !errors.Is(err, ErrUnauthorized)) {
			t.Errorf("basic login with %q: %v", test.pass, err)
		}
	}

	// A registry that doesn't ask for a login can't check one.
	open := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer open.Close()
	client := &Client{HTTP: open.Client(), Scheme: "https", Credentials: func(string) (Credentials, bool) { return Credentials{Username: "u", Password: "p"}, true }}
	if err := client.CheckLogin(context.Background(), strings.TrimPrefix(open.URL, "https://")); !errors.Is(err, ErrLoginNotAsked) {
		t.Errorf("an open registry: %v, want ErrLoginNotAsked", err)
	}
}
