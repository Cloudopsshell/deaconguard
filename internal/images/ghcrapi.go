package images

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
)

// GHCR is ghcr.io, GitHub's container registry.
const GHCR = "ghcr.io"

// GitHubPackagesAPI lists GHCR repositories and tags with GitHub's packages
// API, which says when each image was pushed. It needs a login: the GitHub
// username and a classic personal access token with read:packages, as for
// pulling private images. GitHub's API refuses anonymous and fine-grained
// tokens for packages.
type GitHubPackagesAPI struct {
	Client   *http.Client
	Endpoint string // "" is https://api.github.com
	Token    string
}

func (api GitHubPackagesAPI) endpoint() string {
	if api.Endpoint == "" {
		return "https://api.github.com"
	}
	return strings.TrimSuffix(api.Endpoint, "/")
}

// get reads one page of a GitHub listing, and returns the next page's
// address from its Link header, on the same host only.
func (api GitHubPackagesAPI) get(ctx context.Context, address string, into any) (string, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", 0, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	request.Header.Set("Authorization", "Bearer "+api.Token)
	response, err := api.Client.Do(request)
	if err != nil {
		return "", 0, err
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Message string `json:"message"`
		}
		json.Unmarshal(answer, &failure)
		reason := response.Status
		if failure.Message != "" {
			reason += ": " + failure.Message
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return "", response.StatusCode, fmt.Errorf("%w (GitHub answered %s; its packages API needs a classic token with read:packages)", ErrUnauthorized, reason)
		}
		return "", response.StatusCode, fmt.Errorf("GitHub answered %s", reason)
	}
	if err := json.Unmarshal(answer, into); err != nil {
		return "", 0, fmt.Errorf("unreadable answer from GitHub: %w", err)
	}
	return nextPage(address, response.Header.Get("Link")), response.StatusCode, nil
}

// Tags lists a repository's tags with their digests and when each was
// pushed. repository is owner/package, such as acme/shop or acme/team/shop.
func (api GitHubPackagesAPI) Tags(ctx context.Context, repository string) ([]TagInfo, error) {
	owner, name, ok := strings.Cut(repository, "/")
	if !ok || name == "" {
		return nil, fmt.Errorf("%s is not a GHCR repository, such as acme/shop", repository)
	}
	path := "/packages/container/" + url.PathEscape(name) + "/versions?per_page=100"
	// The owner is an organization, the token's own user (whose private
	// packages only /user shows), or another user.
	bases := []string{"/orgs/" + url.PathEscape(owner), "/user", "/users/" + url.PathEscape(owner)}
	for index, base := range bases {
		tags, found, err := api.versions(ctx, api.endpoint()+base+path)
		if err != nil {
			return nil, fmt.Errorf("ghcr.io/%s: %w", repository, err)
		}
		if found || index == len(bases)-1 {
			if !found {
				return nil, fmt.Errorf("ghcr.io/%s: not found, or its login can't see it", repository)
			}
			return tags, nil
		}
	}
	return nil, nil
}

// versions reads a package's versions; found is false when GitHub doesn't
// know the package at that address.
func (api GitHubPackagesAPI) versions(ctx context.Context, address string) ([]TagInfo, bool, error) {
	var tags []TagInfo
	versions := 0
	for address != "" && versions < maxListed {
		var page []struct {
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Metadata  struct {
				Container struct {
					Tags []string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		next, status, err := api.get(ctx, address, &page)
		if status == http.StatusNotFound && versions == 0 {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		for _, version := range page {
			// Tagging an image again updates its version.
			pushed := version.UpdatedAt
			if pushed.Before(version.CreatedAt) {
				pushed = version.CreatedAt
			}
			digest := version.Name
			if !digestPattern.MatchString(digest) {
				digest = ""
			}
			for _, tag := range version.Metadata.Container.Tags {
				tags = append(tags, TagInfo{Tag: tag, Digest: digest, PushedAt: pushed.UTC()})
			}
		}
		versions += len(page)
		address = next
	}
	return tags, true, nil
}

// Repositories lists the container packages the token's user owns, and
// those of the organizations it belongs to that it can read.
func (api GitHubPackagesAPI) Repositories(ctx context.Context) ([]string, error) {
	names, err := api.packages(ctx, api.endpoint()+"/user/packages?package_type=container&per_page=100")
	if err != nil {
		return nil, fmt.Errorf("ghcr.io: %w", err)
	}
	var orgs []struct {
		Login string `json:"login"`
	}
	if _, _, err := api.get(ctx, api.endpoint()+"/user/orgs?per_page=100", &orgs); err == nil {
		for _, org := range orgs {
			// An organization that refuses the token is left out.
			if more, err := api.packages(ctx, api.endpoint()+"/orgs/"+url.PathEscape(org.Login)+"/packages?package_type=container&per_page=100"); err == nil {
				names = append(names, more...)
			}
		}
	}
	sort.Strings(names)
	return slices.Compact(names), nil
}

func (api GitHubPackagesAPI) packages(ctx context.Context, address string) ([]string, error) {
	var names []string
	for address != "" && len(names) < maxListed {
		var page []struct {
			Name  string `json:"name"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		}
		next, _, err := api.get(ctx, address, &page)
		if err != nil {
			return nil, err
		}
		for _, pkg := range page {
			if pkg.Owner.Login == "" {
				return nil, errors.New("GitHub's answer names no package owner")
			}
			names = append(names, strings.ToLower(pkg.Owner.Login+"/"+pkg.Name))
		}
		address = next
	}
	return names, nil
}
