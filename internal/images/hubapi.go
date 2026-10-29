package images

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
)

// Docker Hub and GHCR don't let the registry API list repositories, nor say
// when a tag was pushed; their own APIs do. Neither reading counts against
// Docker Hub's pull limits.

// maxHubTags caps how many tags one Docker Hub listing reads, newest first:
// 25 requests of the 180 a minute Docker Hub allows. Without a login,
// Docker Hub pages no further than its first 1,000 tags.
const (
	maxHubTags          = 2500
	maxAnonymousHubTags = 1000
)

// HubAPI lists repositories and tags with Docker Hub's API, which says when
// each tag was pushed. Public repositories need no login; private ones, and
// listing a namespace's repositories, need the username and a personal
// access token.
type HubAPI struct {
	Client           *http.Client
	Endpoint         string // "" is https://hub.docker.com
	Username, Secret string
	token            string
}

func (api *HubAPI) endpoint() string {
	if api.Endpoint == "" {
		return "https://hub.docker.com"
	}
	return strings.TrimSuffix(api.Endpoint, "/")
}

// login exchanges the username and access token for a bearer token, once.
func (api *HubAPI) login(ctx context.Context) error {
	if api.token != "" || api.Username == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"identifier": api.Username, "secret": api.Secret})
	var answer struct {
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
	}
	if err := api.send(ctx, http.MethodPost, api.endpoint()+"/v2/auth/token", body, &answer); err != nil {
		return fmt.Errorf("log in to Docker Hub's API as %s: %w", api.Username, err)
	}
	if api.token = answer.AccessToken; api.token == "" {
		api.token = answer.Token
	}
	if api.token == "" {
		return errors.New("log in to Docker Hub's API: no token in its answer")
	}
	return nil
}

func (api *HubAPI) send(ctx context.Context, method, address string, body []byte, into any) error {
	request, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if api.token != "" {
		request.Header.Set("Authorization", "Bearer "+api.token)
	}
	response, err := api.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w (Docker Hub answered %s)", ErrUnauthorized, response.Status)
	case response.StatusCode == http.StatusNotFound:
		return errors.New("not found on Docker Hub, or private: add a login for docker.io")
	case response.StatusCode == http.StatusTooManyRequests:
		return errors.New("Docker Hub's API is limiting requests from this server; try again in a minute")
	case response.StatusCode != http.StatusOK:
		return fmt.Errorf("Docker Hub answered %s", response.Status)
	}
	if err := json.Unmarshal(answer, into); err != nil {
		return fmt.Errorf("unreadable answer from Docker Hub: %w", err)
	}
	return nil
}

// next follows a page's "next" address on the same host only.
func (api *HubAPI) next(link string) string {
	base, err := url.Parse(api.endpoint())
	next, err2 := url.Parse(link)
	if link == "" || err != nil || err2 != nil || next.Host != base.Host || next.Scheme != base.Scheme {
		return ""
	}
	return next.String()
}

// Tags lists a repository's tags, newest first, with their digests and when
// each was last pushed. repository is namespace/name, such as library/alpine.
func (api *HubAPI) Tags(ctx context.Context, repository string) ([]TagInfo, error) {
	namespace, name, ok := strings.Cut(repository, "/")
	if !ok || strings.Contains(name, "/") {
		return nil, fmt.Errorf("%s is not a Docker Hub repository, such as library/alpine", repository)
	}
	if err := api.login(ctx); err != nil {
		return nil, err
	}
	limit := maxHubTags
	if api.token == "" {
		limit = maxAnonymousHubTags
	}
	var tags []TagInfo
	address := fmt.Sprintf("%s/v2/namespaces/%s/repositories/%s/tags?page_size=100&ordering=last_updated", api.endpoint(), url.PathEscape(namespace), url.PathEscape(name))
	for address != "" && len(tags) < limit {
		var page struct {
			Next    string `json:"next"`
			Results []struct {
				Name        string    `json:"name"`
				Digest      string    `json:"digest"`
				LastPushed  time.Time `json:"tag_last_pushed"`
				LastUpdated time.Time `json:"last_updated"`
			} `json:"results"`
		}
		if err := api.send(ctx, http.MethodGet, address, nil, &page); err != nil {
			// Docker Hub may refuse to page further; the newest tags are
			// already read.
			if len(tags) > 0 && errors.Is(err, ErrUnauthorized) {
				break
			}
			return nil, fmt.Errorf("docker.io/%s: %w", repository, err)
		}
		for _, result := range page.Results {
			pushed := result.LastPushed
			if pushed.IsZero() {
				pushed = result.LastUpdated
			}
			digest := result.Digest
			if !digestPattern.MatchString(digest) {
				digest = ""
			}
			tags = append(tags, TagInfo{Tag: result.Name, Digest: digest, PushedAt: pushed.UTC()})
		}
		address = api.next(page.Next)
	}
	return tags, nil
}

// Repositories lists the repositories in the login's own namespace.
func (api *HubAPI) Repositories(ctx context.Context) ([]string, error) {
	if api.Username == "" {
		return nil, ErrListingRefused
	}
	if err := api.login(ctx); err != nil {
		return nil, err
	}
	namespace := strings.ToLower(api.Username)
	var names []string
	address := fmt.Sprintf("%s/v2/namespaces/%s/repositories?page_size=100", api.endpoint(), url.PathEscape(namespace))
	for address != "" && len(names) < maxListed {
		var page struct {
			Next    string `json:"next"`
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		if err := api.send(ctx, http.MethodGet, address, nil, &page); err != nil {
			return nil, fmt.Errorf("docker.io/%s: %w", namespace, err)
		}
		for _, result := range page.Results {
			names = append(names, namespace+"/"+result.Name)
		}
		address = api.next(page.Next)
	}
	sort.Strings(names)
	return names, nil
}
