// Package osv checks application libraries against OSV (https://osv.dev),
// the open vulnerability database for npm, PyPI, Go, RubyGems, crates.io,
// Packagist and more. Only the server talks to OSV: it sends each library's
// ecosystem, name and version to api.osv.dev, never a host name, address or
// path, and keeps the vulnerability records it gets back for a day.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/libraries"
	"deaconguard/internal/store"
)

// DefaultBaseURL is OSV's API.
const DefaultBaseURL = "https://api.osv.dev"

const (
	batchSize      = 1000
	recordTTL      = 24 * time.Hour
	maxRecordBytes = 4 << 20
	maxBatchBytes  = 32 << 20
	fetchWorkers   = 8
)

// HTTPClient is what the client needs from *http.Client.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client queries OSV and caches its vulnerability records on disk.
type Client struct {
	HTTP    HTTPClient
	BaseURL string
	// CacheDir holds one JSON file per vulnerability record.
	CacheDir string
	Now      func() time.Time
}

// NewClient returns a client for api.osv.dev that caches in the data directory.
func NewClient() *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		BaseURL:  DefaultBaseURL,
		CacheDir: filepath.Join(store.DataDir(), "feeds", "osv"),
		Now:      time.Now,
	}
}

// Vulnerability is the part of an OSV record DeaconGuard uses.
type Vulnerability struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type query struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type queryResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// Match is a library and the IDs of the vulnerabilities OSV lists for it.
type Match struct {
	Library libraries.Library
	IDs     []string
}

// Query asks OSV which vulnerabilities affect each library, in batches.
func (c *Client) Query(ctx context.Context, libs []libraries.Library) ([]Match, error) {
	var matches []Match
	for start := 0; start < len(libs); start += batchSize {
		end := min(start+batchSize, len(libs))
		batch := make([]query, 0, end-start)
		for _, library := range libs[start:end] {
			var q query
			q.Package.Name, q.Package.Ecosystem, q.Version = library.Name, library.Ecosystem, library.Version
			batch = append(batch, q)
		}
		var response struct {
			Results []queryResult `json:"results"`
		}
		if err := c.post(ctx, "/v1/querybatch", map[string]any{"queries": batch}, maxBatchBytes, &response); err != nil {
			return nil, err
		}
		if len(response.Results) != len(batch) {
			return nil, fmt.Errorf("OSV answered %d results for %d libraries", len(response.Results), len(batch))
		}
		for index, result := range response.Results {
			ids := idsOf(result)
			// A library with more vulnerabilities than fit in one batch answer
			// is asked about again on its own, page by page.
			for token := result.NextPageToken; token != ""; {
				q := batch[index]
				q.PageToken = token
				var page queryResult
				if err := c.post(ctx, "/v1/query", q, maxBatchBytes, &page); err != nil {
					return nil, err
				}
				ids = append(ids, idsOf(page)...)
				token = page.NextPageToken
			}
			if len(ids) > 0 {
				matches = append(matches, Match{Library: libs[start+index], IDs: ids})
			}
		}
	}
	return matches, nil
}

func idsOf(result queryResult) []string {
	ids := make([]string, 0, len(result.Vulns))
	for _, vuln := range result.Vulns {
		if validID.MatchString(vuln.ID) {
			ids = append(ids, vuln.ID)
		}
	}
	return ids
}

// validID keeps IDs safe to use as a URL path segment and a file name.
var validID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,99}$`)

// Records fetches the vulnerability records for ids, from the cache when it
// is less than a day old. A record that can't be fetched but was cached
// before is used anyway; one that was never cached is an error.
func (c *Client) Records(ctx context.Context, ids []string) (map[string]Vulnerability, error) {
	records := make(map[string]Vulnerability, len(ids))
	var mu sync.Mutex
	var firstErr error
	work := make(chan string)
	var wg sync.WaitGroup
	for range fetchWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				record, err := c.record(ctx, id)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				} else if err == nil {
					records[id] = record
				}
				mu.Unlock()
			}
		}()
	}
	seen := make(map[string]bool)
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			work <- id
		}
	}
	close(work)
	wg.Wait()
	return records, firstErr
}

func (c *Client) record(ctx context.Context, id string) (Vulnerability, error) {
	path := filepath.Join(c.CacheDir, strings.ReplaceAll(id, ":", "_")+".json")
	cached, cacheErr := readRecord(path)
	if cacheErr == nil {
		if info, err := os.Stat(path); err == nil && c.Now().Sub(info.ModTime()) < recordTTL {
			return cached, nil
		}
	}
	var record Vulnerability
	raw, err := c.get(ctx, "/v1/vulns/"+url.PathEscape(id), maxRecordBytes)
	if err == nil {
		err = json.Unmarshal(raw, &record)
	}
	if err != nil {
		if cacheErr == nil {
			return cached, nil
		}
		return Vulnerability{}, fmt.Errorf("fetch %s from OSV: %w", id, err)
	}
	if mkErr := os.MkdirAll(c.CacheDir, 0o700); mkErr == nil {
		temporary := path + ".tmp"
		if os.WriteFile(temporary, raw, 0o600) == nil {
			_ = os.Rename(temporary, path)
		}
	}
	return record, nil
}

func readRecord(path string) (Vulnerability, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Vulnerability{}, err
	}
	var record Vulnerability
	err = json.Unmarshal(raw, &record)
	return record, err
}

func (c *Client) post(ctx context.Context, path string, body any, limit int64, into any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	raw, err := c.do(request, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (c *Client) get(ctx context.Context, path string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(request, limit)
}

func (c *Client) do(request *http.Request, limit int64) ([]byte, error) {
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	request.Header.Set("Accept", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("OSV's answer is too large")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV answered %s", response.Status)
	}
	return raw, nil
}
