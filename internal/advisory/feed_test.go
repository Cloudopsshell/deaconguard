package advisory

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) Do(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestLoadFeedFetchesAndCachesOfficialDataPrivately(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("DEACONGUARD_HOME", directory)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("User-Agent") == "" {
			t.Fatal("missing user agent")
		}
		return &http.Response{
			StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("official feed")),
			Header: http.Header{"Last-Modified": []string{"Sat, 26 Sep 2026 11:00:00 GMT"}},
		}, nil
	})
	feed, err := LoadFeed("https://vendor.example/security.json", "debian-bookworm", client, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(feed.Data) != "official feed" || feed.Metadata.Stale || feed.Metadata.SHA256 == "" {
		t.Fatalf("unexpected fetched feed: %+v", feed.Metadata)
	}
	info, err := os.Stat(filepath.Join(directory, "feeds", "debian-bookworm.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache permissions = %v, %v; want 0600", info, err)
	}
	cacheClient := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("fresh cache unexpectedly made a network request")
		return nil, nil
	})
	cached, err := LoadFeed("https://vendor.example/security.json", "debian-bookworm", cacheClient, now.Add(time.Hour))
	if err != nil || !bytes.Equal(cached.Data, feed.Data) {
		t.Fatalf("cached feed = %+v, %v", cached, err)
	}
}

func TestLoadFeedUsesStaleCacheOnRefreshFailure(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	working := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("cached source")), Header: make(http.Header)}, nil
	})
	if _, err := LoadFeed("https://vendor.example/security.json", "rhel-9", working, now); err != nil {
		t.Fatal(err)
	}
	failing := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	feed, err := LoadFeed("https://vendor.example/security.json", "rhel-9", failing, now.Add(13*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !feed.Metadata.Stale || feed.Metadata.RefreshError == "" || string(feed.Data) != "cached source" {
		t.Fatalf("stale cache was not marked correctly: %+v", feed.Metadata)
	}
}

func TestLoadFeedFailsWithoutCacheAndOnOversizedResponse(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	failing := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if _, err := LoadFeed("https://vendor.example/security.json", "missing", failing, time.Now()); err == nil {
		t.Fatal("expected a missing cache and failed fetch to fail")
	}
	oversized := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxCompressed+1))), Header: make(http.Header)}, nil
	})
	if _, err := LoadFeed("https://vendor.example/security.json", "oversized", oversized, time.Now()); err == nil {
		t.Fatal("expected oversized response to fail")
	}
}

func TestLoadFeedAcceptsTypedNilHTTPClient(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "fixture feed")
	}))
	defer server.Close()
	var nilClient *http.Client
	feed, err := LoadFeed(server.URL, "typed-nil-client", nilClient, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if string(feed.Data) != "fixture feed" {
		t.Fatalf("unexpected feed body %q", feed.Data)
	}
}
