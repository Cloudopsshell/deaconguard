package advisory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"opsarmor/internal/buildinfo"
	"opsarmor/internal/platform"
	"opsarmor/internal/store"
)

const (
	feedTTL            = 12 * time.Hour
	maxCompressed      = 128 << 20
	defaultHTTPTimeout = 45 * time.Second
)

type FeedMetadata struct {
	Source       string    `json:"source"`
	FetchedAt    time.Time `json:"fetched_at"`
	SHA256       string    `json:"sha256"`
	Stale        bool      `json:"feed_stale"`
	AgeHours     float64   `json:"feed_age_hours"`
	RefreshError string    `json:"feed_refresh_error,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
}

func LoadDebianTracker(target platform.Platform, client HTTPClient, now time.Time) (Feed, error) {
	if target.Family != platform.Debian || (target.Codename != "bookworm" && target.Codename != "trixie") {
		return Feed{}, fmt.Errorf("Debian tracker is unavailable for this platform")
	}
	return LoadFeed("https://security-tracker.debian.org/tracker/data/json", "debian-security-tracker", client, now)
}

func LoadUbuntuOVAL(target platform.Platform, client HTTPClient, now time.Time) (Feed, error) {
	if target.Family != platform.Ubuntu || target.Codename == "" {
		return Feed{}, fmt.Errorf("Canonical OVAL is unavailable for this platform")
	}
	url := fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2", target.Codename)
	return LoadFeed(url, "ubuntu-"+target.Codename+"-oval", client, now)
}

func LoadRedHatOVAL(target platform.Platform, client HTTPClient, now time.Time) (Feed, error) {
	if target.Family != platform.RHEL || (target.Major != 8 && target.Major != 9) {
		return Feed{}, fmt.Errorf("Red Hat OVAL is available only for verified RHEL 8 and 9 feeds")
	}
	url := fmt.Sprintf("https://security.access.redhat.com/data/oval/v2/RHEL%d/rhel-%d.oval.xml.bz2", target.Major, target.Major)
	return LoadFeed(url, fmt.Sprintf("rhel-%d-oval", target.Major), client, now)
}

func LoadAmazonLinux2023RSS(target platform.Platform, client HTTPClient, now time.Time) (Feed, error) {
	if target.Family != platform.AmazonLinux {
		return Feed{}, fmt.Errorf("ALAS 2023 advisories are unavailable for this platform")
	}
	return LoadFeed("https://alas.aws.amazon.com/AL2023/alas.rss", "alas-2023-rss", client, now)
}

type Feed struct {
	Data     []byte
	Metadata FeedMetadata
}

type cachedEnvelope struct {
	Metadata FeedMetadata `json:"metadata"`
	Data     []byte       `json:"data"`
}

type HTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

func LoadFeed(source, cacheName string, client HTTPClient, now time.Time) (Feed, error) {
	if client == nil || isNilHTTPClient(client) {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cacheDirectory := filepath.Join(store.DataDir(), "feeds")
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		return Feed{}, err
	}
	cachePath := filepath.Join(cacheDirectory, cacheName+".json")
	cached, cachedErr := readCache(cachePath)
	if cachedErr == nil && now.Sub(cached.Metadata.FetchedAt) < feedTTL {
		cached.Metadata.Stale = false
		cached.Metadata.AgeHours = ageHours(now.Sub(cached.Metadata.FetchedAt))
		return cached, nil
	}

	request, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return staleOrError(cached, cachedErr, fmt.Errorf("create advisory request: %w", err), now)
	}
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	response, err := client.Do(request)
	if err != nil {
		return staleOrError(cached, cachedErr, fmt.Errorf("fetch advisory feed: %w", err), now)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return staleOrError(cached, cachedErr, fmt.Errorf("advisory feed returned HTTP %d", response.StatusCode), now)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxCompressed+1))
	if err != nil {
		return staleOrError(cached, cachedErr, fmt.Errorf("read advisory feed: %w", err), now)
	}
	if len(data) > maxCompressed {
		return staleOrError(cached, cachedErr, fmt.Errorf("advisory feed exceeds %d bytes", maxCompressed), now)
	}
	if len(data) == 0 {
		return staleOrError(cached, cachedErr, fmt.Errorf("advisory feed is empty"), now)
	}
	digest := sha256.Sum256(data)
	feed := Feed{Data: data, Metadata: FeedMetadata{
		Source: source, FetchedAt: now.UTC(), SHA256: hex.EncodeToString(digest[:]),
		LastModified: response.Header.Get("Last-Modified"), AgeHours: 0,
	}}
	if err := writeCache(cachePath, cachedEnvelope{Metadata: feed.Metadata, Data: data}); err != nil {
		return Feed{}, fmt.Errorf("cache advisory feed: %w", err)
	}
	return feed, nil
}

func isNilHTTPClient(client HTTPClient) bool {
	concrete, ok := client.(*http.Client)
	return ok && concrete == nil
}

func readCache(path string) (Feed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Feed{}, err
	}
	var envelope cachedEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Feed{}, err
	}
	if len(envelope.Data) == 0 || envelope.Metadata.FetchedAt.IsZero() {
		return Feed{}, fmt.Errorf("invalid advisory cache")
	}
	return Feed{Data: envelope.Data, Metadata: envelope.Metadata}, nil
}

func writeCache(path string, envelope cachedEnvelope) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".feed-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(envelope); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func staleOrError(cached Feed, cacheErr, refreshErr error, now time.Time) (Feed, error) {
	if cacheErr != nil {
		return Feed{}, fmt.Errorf("no usable advisory feed cache; %w", refreshErr)
	}
	cached.Metadata.Stale = true
	cached.Metadata.AgeHours = ageHours(now.Sub(cached.Metadata.FetchedAt))
	cached.Metadata.RefreshError = refreshErr.Error()
	return cached, nil
}

func ageHours(age time.Duration) float64 {
	if age < 0 {
		age = 0
	}
	return float64(age.Round(time.Minute)) / float64(time.Hour)
}
