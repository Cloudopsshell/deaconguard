package images

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/buildinfo"
)

// Credentials log in to a registry. An empty Username is anonymous.
type Credentials struct {
	Username string
	Password string
}

// Client talks to registries with the Docker Registry HTTP API v2, which
// every registry DeaconGuard supports implements.
type Client struct {
	HTTP *http.Client
	// Credentials returns the login for a registry host, if there is one.
	Credentials func(registry string) (Credentials, bool)
	// Scheme is https, or http for a test registry.
	Scheme string

	mu     sync.Mutex
	tokens map[string]string // registry and repository -> bearer token
}

// NewClient returns a client with the given logins.
func NewClient(credentials func(string) (Credentials, bool)) *Client {
	return &Client{HTTP: &http.Client{Timeout: 10 * time.Minute}, Credentials: credentials, Scheme: "https"}
}

const (
	mediaOCIIndex     = "application/vnd.oci.image.index.v1+json"
	mediaDockerList   = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerSchema = "application/vnd.docker.distribution.manifest.v2+json"
	maxManifestBytes  = 4 << 20
)

// Descriptor points at a manifest or blob.
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    Descriptor   `json:"config"`
	Layers    []Descriptor `json:"layers"`
	Manifests []Descriptor `json:"manifests"`
}

// isIndex reports whether the manifest lists an image per platform.
func (m manifest) isIndex(mediaType string) bool {
	if mediaType == "" {
		mediaType = m.MediaType
	}
	return mediaType == mediaOCIIndex || mediaType == mediaDockerList || (len(m.Manifests) > 0 && len(m.Layers) == 0)
}

// choose picks platform's manifest from an index, and says which platforms
// exist if it isn't one of them.
func (m manifest) choose(platform, name string) (Descriptor, error) {
	var available []string
	for _, d := range m.Manifests {
		if d.Platform == nil || d.Platform.OS == "unknown" {
			continue // attestations
		}
		option := d.Platform.OS + "/" + d.Platform.Architecture
		if d.Platform.Variant != "" && d.Platform.Architecture != "amd64" {
			option += "/" + d.Platform.Variant
		}
		available = append(available, option)
		if option == platform || strings.HasPrefix(option, platform+"/") {
			return d, nil
		}
	}
	if len(available) == 0 && len(m.Manifests) == 1 {
		return m.Manifests[0], nil // a single image without a platform
	}
	return Descriptor{}, fmt.Errorf("%s has no %s image; it has %s", name, platform, strings.Join(available, ", "))
}

// ErrUnauthorized means the registry wants a login DeaconGuard doesn't have,
// or refused the one it has.
var ErrUnauthorized = errors.New("the registry refused access: add a login for it, or check the one saved")

// Resolved is an image's manifest for one platform.
type Resolved struct {
	Reference Reference
	// Digest is the platform manifest's digest: the image's ID in the registry.
	Digest string
	// TagDigest is the digest the reference points to, an index for a
	// multi-platform image; TagDigest tells when the tag moves.
	TagDigest string
	Platform  string
	Layers    []Descriptor
}

// Resolve fetches an image's manifest. For a multi-platform image, it
// picks platform, such as linux/amd64, and says which ones exist if it isn't
// one of them.
func (c *Client) Resolve(ctx context.Context, ref Reference, platform string) (Resolved, error) {
	body, mediaType, digest, err := c.getManifest(ctx, ref, ref.reference())
	if err != nil {
		return Resolved{}, err
	}
	tagDigest := digest
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Resolved{}, fmt.Errorf("read the manifest of %s: %w", ref, err)
	}
	if mediaType == "" {
		mediaType = m.MediaType
	}
	if m.isIndex(mediaType) {
		chosen, err := m.choose(platform, ref.String())
		if err != nil {
			return Resolved{}, err
		}
		body, _, digest, err = c.getManifest(ctx, ref, chosen.Digest)
		if err != nil {
			return Resolved{}, err
		}
		m = manifest{}
		if err := json.Unmarshal(body, &m); err != nil {
			return Resolved{}, fmt.Errorf("read the %s manifest of %s: %w", platform, ref, err)
		}
	}
	if len(m.Layers) == 0 {
		return Resolved{}, fmt.Errorf("%s has no layers", ref)
	}
	return Resolved{Reference: ref, Digest: digest, TagDigest: tagDigest, Platform: platform, Layers: m.Layers}, nil
}

// manifestTypes are the manifests DeaconGuard reads, as an Accept header.
var manifestTypes = strings.Join([]string{mediaOCIIndex, mediaDockerList, mediaOCIManifest, mediaDockerSchema}, ", ")

// TagDigest asks the registry which digest the reference points to now,
// without downloading anything: a HEAD request, which Docker Hub doesn't
// count against its pull limits. It is Resolved.TagDigest when unchanged.
func (c *Client) TagDigest(ctx context.Context, ref Reference) (string, error) {
	if ref.Digest != "" {
		return ref.Digest, nil
	}
	response, err := c.request(ctx, http.MethodHead, ref, "/manifests/"+ref.reference(), manifestTypes)
	if err != nil {
		return "", err
	}
	response.Body.Close()
	if digest := response.Header.Get("Docker-Content-Digest"); digestPattern.MatchString(digest) {
		return digest, nil
	}
	// Registries needn't send the digest; read the manifest instead.
	_, _, digest, err := c.getManifest(ctx, ref, ref.reference())
	return digest, err
}

func (c *Client) getManifest(ctx context.Context, ref Reference, reference string) ([]byte, string, string, error) {
	response, err := c.get(ctx, ref, "/manifests/"+reference, manifestTypes)
	if err != nil {
		return nil, "", "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
	if err != nil {
		return nil, "", "", err
	}
	if len(body) > maxManifestBytes {
		return nil, "", "", fmt.Errorf("the manifest of %s is larger than 4 MB", ref)
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(reference, "sha256:") && reference != digest {
		return nil, "", "", fmt.Errorf("the registry's manifest for %s doesn't match its digest", ref)
	}
	mediaType, _, _ := strings.Cut(response.Header.Get("Content-Type"), ";")
	return body, strings.TrimSpace(mediaType), digest, nil
}

// Blob opens a layer. Reading it to the end checks it against its digest;
// a mismatch is an error from the last Read.
func (c *Client) Blob(ctx context.Context, ref Reference, layer Descriptor) (io.ReadCloser, error) {
	if !digestPattern.MatchString(layer.Digest) {
		return nil, fmt.Errorf("unsupported layer digest %q", layer.Digest)
	}
	response, err := c.get(ctx, ref, "/blobs/"+layer.Digest, "*/*")
	if err != nil {
		return nil, err
	}
	return &verified{ReadCloser: response.Body, hash: sha256.New(), want: strings.TrimPrefix(layer.Digest, "sha256:")}, nil
}

type verified struct {
	io.ReadCloser
	hash     hash.Hash
	want     string
	done     bool
	mismatch error
}

func (v *verified) Read(p []byte) (int, error) {
	n, err := v.ReadCloser.Read(p)
	v.hash.Write(p[:n])
	if errors.Is(err, io.EOF) && !v.done {
		v.done = true
		if hex.EncodeToString(v.hash.Sum(nil)) != v.want {
			v.mismatch = fmt.Errorf("a layer doesn't match its digest sha256:%s", v.want)
			return n, v.mismatch
		}
	}
	return n, err
}

// Verify says whether the whole layer was read and matched its digest. It
// doesn't depend on the readers above passing the error on: decompressors
// read ahead and may keep it.
func (v *verified) Verify() error {
	if v.mismatch != nil {
		return v.mismatch
	}
	if !v.done {
		return fmt.Errorf("the layer sha256:%s wasn't read to its end", v.want)
	}
	return nil
}

// get requests a path under the repository, logging in when the registry
// asks: with a bearer token from its token service (anonymous, or with the
// saved login), or with basic authentication.
func (c *Client) get(ctx context.Context, ref Reference, path, accept string) (*http.Response, error) {
	return c.request(ctx, http.MethodGet, ref, path, accept)
}

func (c *Client) request(ctx context.Context, method string, ref Reference, path, accept string) (*http.Response, error) {
	address := fmt.Sprintf("%s://%s/v2/%s%s", c.Scheme, ref.Registry, ref.Repository, path)
	key := ref.Registry + "/" + ref.Repository
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, address, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", accept)
		request.Header.Set("User-Agent", buildinfo.UserAgent())
		c.mu.Lock()
		token := c.tokens[key]
		c.mu.Unlock()
		if token != "" {
			request.Header.Set("Authorization", token)
		}
		response, err := c.HTTP.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusOK {
			return response, nil
		}
		challenge := response.Header.Get("WWW-Authenticate")
		io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		switch {
		case response.StatusCode == http.StatusUnauthorized && attempt == 0 && challenge != "":
			authorization, err := c.login(ctx, ref, challenge)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			if c.tokens == nil {
				c.tokens = make(map[string]string)
			}
			c.tokens[key] = authorization
			c.mu.Unlock()
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			return nil, fmt.Errorf("%s: %w", ref, ErrUnauthorized)
		case response.StatusCode == http.StatusNotFound:
			return nil, fmt.Errorf("%s: not found in the registry (or it's private and needs a login)", ref)
		case response.StatusCode == http.StatusTooManyRequests:
			return nil, fmt.Errorf("%s: the registry is rate-limiting requests; try again later, or add a login for it", ref)
		default:
			return nil, fmt.Errorf("%s: the registry answered %s", ref, response.Status)
		}
	}
	return nil, fmt.Errorf("%s: %w", ref, ErrUnauthorized)
}

// login answers a WWW-Authenticate challenge.
func (c *Client) login(ctx context.Context, ref Reference, challenge string) (string, error) {
	credentials, haveLogin := Credentials{}, false
	if c.Credentials != nil {
		credentials, haveLogin = c.Credentials(ref.Registry)
	}
	scheme, params := parseChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		if !haveLogin {
			return "", fmt.Errorf("%s: %w", ref, ErrUnauthorized)
		}
		request, _ := http.NewRequest(http.MethodGet, "http://x", nil)
		request.SetBasicAuth(credentials.Username, credentials.Password)
		return request.Header.Get("Authorization"), nil
	case "bearer":
		if !haveLogin {
			credentials = Credentials{}
		}
		return c.bearerToken(ctx, ref.String(), ref.Registry, params, "repository:"+ref.Repository+":pull", credentials)
	}
	return "", fmt.Errorf("%s: the registry asks for a %q login, which DeaconGuard doesn't support", ref, scheme)
}

// bearerToken gets a token from the login service a Bearer challenge names,
// for scope (none to just log in), with the credentials if there are any.
// what names the image or registry in errors.
func (c *Client) bearerToken(ctx context.Context, what, registry string, params map[string]string, scope string, credentials Credentials) (string, error) {
	realm, err := url.Parse(params["realm"])
	if err != nil || (realm.Scheme != "https" && realm.Scheme != c.Scheme) || realm.Host == "" {
		return "", fmt.Errorf("%s: the registry's login address %q isn't usable", what, params["realm"])
	}
	query := realm.Query()
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	if scope != "" {
		query.Set("scope", scope)
	} else if credentials.Username != "" {
		// Logging in without a scope, as docker login does.
		query.Set("account", credentials.Username)
	}
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	if credentials.Username != "" {
		request.SetBasicAuth(credentials.Username, credentials.Password)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return "", fmt.Errorf("log in to %s: %w", registry, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %w (the login service answered %s)", what, ErrUnauthorized, response.Status)
	}
	var answer struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&answer); err != nil {
		return "", fmt.Errorf("log in to %s: %w", registry, err)
	}
	token := answer.Token
	if token == "" {
		token = answer.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("%s: %w", what, ErrUnauthorized)
	}
	return "Bearer " + token, nil
}

// ErrLoginNotAsked means the registry answered without asking for a login,
// so it didn't check the one given; it is still used when an image needs it.
var ErrLoginNotAsked = errors.New("the registry answers without a login, so it couldn't check this one; DeaconGuard uses it when an image needs it")

// CheckLogin logs in to a registry the way docker login does: it asks the
// registry how to log in, logs in with the registry's login, and checks that
// the registry accepts the result. nil means the login works.
func (c *Client) CheckLogin(ctx context.Context, registry string) error {
	address := fmt.Sprintf("%s://%s/v2/", c.Scheme, registry)
	ask := func(authorization string) (int, string, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return 0, "", err
		}
		request.Header.Set("User-Agent", buildinfo.UserAgent())
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, err := c.HTTP.Do(request)
		if err != nil {
			return 0, "", fmt.Errorf("reach %s: %w", registry, err)
		}
		defer response.Body.Close()
		io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return response.StatusCode, response.Header.Get("WWW-Authenticate"), nil
	}
	status, challenge, err := ask("")
	switch {
	case err != nil:
		return err
	case status == http.StatusOK:
		return fmt.Errorf("%s: %w", registry, ErrLoginNotAsked)
	case status != http.StatusUnauthorized:
		return fmt.Errorf("%s: the registry answered %s", registry, http.StatusText(status))
	case challenge == "":
		return fmt.Errorf("%s: the registry asks for a login without saying how", registry)
	}
	credentials, haveLogin := Credentials{}, false
	if c.Credentials != nil {
		credentials, haveLogin = c.Credentials(registry)
	}
	if !haveLogin || credentials.Username == "" {
		return fmt.Errorf("%s: %w", registry, ErrUnauthorized)
	}
	var authorization string
	scheme, params := parseChallenge(challenge)
	switch strings.ToLower(scheme) {
	case "basic":
		request, _ := http.NewRequest(http.MethodGet, "http://x", nil)
		request.SetBasicAuth(credentials.Username, credentials.Password)
		authorization = request.Header.Get("Authorization")
	case "bearer":
		if authorization, err = c.bearerToken(ctx, registry, registry, params, "", credentials); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: the registry asks for a %q login, which DeaconGuard doesn't support", registry, scheme)
	}
	switch status, _, err := ask(authorization); {
	case err != nil:
		return err
	case status == http.StatusOK:
		return nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%s: %w", registry, ErrUnauthorized)
	default:
		return fmt.Errorf("%s: the registry answered %s", registry, http.StatusText(status))
	}
}

// parseChallenge reads `Bearer realm="…",service="…",scope="…"`.
func parseChallenge(header string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	params := make(map[string]string)
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		key, value, found := strings.Cut(rest, "=")
		if !found {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(value, `"`) {
			end := strings.Index(value[1:], `"`)
			if end < 0 {
				break
			}
			params[key], rest = value[1:end+1], value[end+2:]
		} else {
			comma := strings.Index(value, ",")
			if comma < 0 {
				params[key], rest = value, ""
			} else {
				params[key], rest = value[:comma], value[comma+1:]
			}
		}
	}
	return scheme, params
}
