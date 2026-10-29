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

// Quay, Harbor and GitLab have APIs of their own, beside the registry API,
// that say when each tag was pushed. Quay and GitLab answer for public
// repositories without a login; Harbor takes the registry login.

// Flavor names a registry whose own API DeaconGuard reads.
type Flavor string

const (
	FlavorNone   Flavor = ""
	FlavorQuay   Flavor = "quay"
	FlavorHarbor Flavor = "harbor"
	FlavorGitLab Flavor = "gitlab"
)

// apiCall is one request to a registry's own API.
type apiCall struct {
	client        *http.Client
	method, url   string
	body          []byte
	authorization string
}

// do sends the call and decodes a 200 answer into into; it returns the
// answer's headers for paging.
func (call apiCall) do(ctx context.Context, name string, into any) (http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, call.method, call.url, bytes.NewReader(call.body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	if call.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if call.authorization != "" {
		request.Header.Set("Authorization", call.authorization)
	}
	response, err := call.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w (%s's API answered %s)", ErrUnauthorized, name, response.Status)
	case response.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("not found by %s's API, or private: add a login for it", name)
	case response.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%s's API is limiting requests from this server; try again later", name)
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s's API answered %s", name, response.Status)
	}
	if err := json.Unmarshal(answer, into); err != nil {
		return nil, fmt.Errorf("unreadable answer from %s's API: %w", name, err)
	}
	return response.Header, nil
}

func basicAuthorization(username, password string) string {
	request := http.Request{Header: http.Header{}}
	request.SetBasicAuth(username, password)
	return request.Header.Get("Authorization")
}

// DetectFlavor asks a registry host whether it is Quay, Harbor or GitLab,
// each by a request that needs no login, and returns the address of its
// API. GitLab's is on another host, gitlab.example.com for
// registry.gitlab.example.com or gitlab.example.com:5050, and only hosts
// with gitlab in their name are asked.
func DetectFlavor(ctx context.Context, client *http.Client, scheme, registry string) (Flavor, string) {
	switch registry {
	case "quay.io":
		return FlavorQuay, scheme + "://quay.io"
	case "registry.gitlab.com":
		return FlavorGitLab, "https://gitlab.com"
	}
	base := scheme + "://" + registry
	var harbor map[string]any
	if _, err := (apiCall{client: client, method: http.MethodGet, url: base + "/api/v2.0/systeminfo"}).do(ctx, "Harbor", &harbor); err == nil {
		if _, ok := harbor["auth_mode"]; ok {
			return FlavorHarbor, base
		}
	}
	var quay struct {
		Info struct {
			Title string `json:"title"`
		} `json:"info"`
	}
	if _, err := (apiCall{client: client, method: http.MethodGet, url: base + "/api/v1/discovery"}).do(ctx, "Quay", &quay); err == nil && strings.Contains(quay.Info.Title, "Quay") {
		return FlavorQuay, base
	}
	// GitLab only on hosts named for it, so that no other site is asked.
	for _, candidate := range gitLabHosts(registry) {
		api := scheme + "://" + candidate
		var answer struct {
			Data struct {
				Typename string `json:"__typename"`
			} `json:"data"`
		}
		call := apiCall{client: client, method: http.MethodPost, url: api + "/api/graphql", body: []byte(`{"query":"{ __typename }"}`)}
		if _, err := call.do(ctx, "GitLab", &answer); err == nil && answer.Data.Typename == "Query" {
			return FlavorGitLab, api
		}
	}
	return FlavorNone, ""
}

// gitLabHosts are the hosts that may serve GitLab's API for a registry.
func gitLabHosts(registry string) []string {
	host, port, _ := strings.Cut(registry, ":")
	if !strings.Contains(host, "gitlab") {
		return nil
	}
	if rest, ok := strings.CutPrefix(host, "registry."); ok {
		return []string{rest}
	}
	if port != "" {
		return []string{host}
	}
	return nil
}

// QuayAPI lists tags with Quay's API (quay.io, or Red Hat Quay). Public
// repositories need no login; for private ones, the login is the username
// $oauthtoken and an OAuth access token, which Quay's API takes too.
// Robot accounts work for the registry only.
type QuayAPI struct {
	Client   *http.Client
	Endpoint string
	Token    string
}

// Tags lists a repository's tags, with their digests and when each was
// pushed.
func (api QuayAPI) Tags(ctx context.Context, repository string) ([]TagInfo, error) {
	authorization := ""
	if api.Token != "" {
		authorization = "Bearer " + api.Token
	}
	var tags []TagInfo
	for page := 1; len(tags) < maxListed; page++ {
		var answer struct {
			Tags []struct {
				Name    string `json:"name"`
				Digest  string `json:"manifest_digest"`
				StartTS int64  `json:"start_ts"`
			} `json:"tags"`
			HasAdditional bool `json:"has_additional"`
		}
		address := fmt.Sprintf("%s/api/v1/repository/%s/tag/?limit=100&page=%d&onlyActiveTags=true", api.Endpoint, escapePath(repository), page)
		if _, err := (apiCall{client: api.Client, method: http.MethodGet, url: address, authorization: authorization}).do(ctx, "Quay", &answer); err != nil {
			return nil, err
		}
		for _, tag := range answer.Tags {
			info := TagInfo{Tag: tag.Name}
			if digestPattern.MatchString(tag.Digest) {
				info.Digest = tag.Digest
			}
			if tag.StartTS > 0 {
				info.PushedAt = time.Unix(tag.StartTS, 0).UTC()
			}
			tags = append(tags, info)
		}
		if !answer.HasAdditional || len(answer.Tags) == 0 {
			break
		}
	}
	return tags, nil
}

// HarborAPI lists repositories and tags with Harbor's API, with the
// registry login (a user or a robot account), or none for public projects.
type HarborAPI struct {
	Client             *http.Client
	Endpoint           string
	Username, Password string
}

func (api HarborAPI) authorization() string {
	if api.Username == "" {
		return ""
	}
	return basicAuthorization(api.Username, api.Password)
}

// Tags lists a repository's tags, project/name, with their digests and
// when each was pushed.
func (api HarborAPI) Tags(ctx context.Context, repository string) ([]TagInfo, error) {
	project, name, ok := strings.Cut(repository, "/")
	if !ok || name == "" {
		return nil, fmt.Errorf("%s is not a Harbor repository, such as project/app", repository)
	}
	// Harbor wants a repository name with slashes escaped twice.
	path := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts", api.Endpoint, url.PathEscape(project), url.PathEscape(url.PathEscape(name)))
	var tags []TagInfo
	for page := 1; len(tags) < maxListed; page++ {
		var artifacts []struct {
			Digest   string    `json:"digest"`
			PushTime time.Time `json:"push_time"`
			Tags     []struct {
				Name     string    `json:"name"`
				PushTime time.Time `json:"push_time"`
			} `json:"tags"`
		}
		address := fmt.Sprintf("%s?with_tag=true&page_size=100&page=%d", path, page)
		if _, err := (apiCall{client: api.Client, method: http.MethodGet, url: address, authorization: api.authorization()}).do(ctx, "Harbor", &artifacts); err != nil {
			return nil, err
		}
		for _, artifact := range artifacts {
			digest := artifact.Digest
			if !digestPattern.MatchString(digest) {
				digest = ""
			}
			for _, tag := range artifact.Tags {
				pushed := tag.PushTime
				if pushed.IsZero() {
					pushed = artifact.PushTime
				}
				tags = append(tags, TagInfo{Tag: tag.Name, Digest: digest, PushedAt: pushed.UTC()})
			}
		}
		if len(artifacts) < 100 {
			break
		}
	}
	return tags, nil
}

// Repositories lists every repository the login can see.
func (api HarborAPI) Repositories(ctx context.Context) ([]string, error) {
	var names []string
	for page := 1; len(names) < maxListed; page++ {
		var repositories []struct {
			Name string `json:"name"`
		}
		address := fmt.Sprintf("%s/api/v2.0/repositories?page_size=100&page=%d", api.Endpoint, page)
		if _, err := (apiCall{client: api.Client, method: http.MethodGet, url: address, authorization: api.authorization()}).do(ctx, "Harbor", &repositories); err != nil {
			return nil, err
		}
		for _, repository := range repositories {
			names = append(names, repository.Name)
		}
		if len(repositories) < 100 {
			break
		}
	}
	sort.Strings(names)
	return names, nil
}

// GitLabAPI lists a repository's tags with GitLab's GraphQL API, which says
// when each was published. Public projects need no login; private ones a
// personal, project or group access token with read_api (a deploy token
// works for the registry only), saved as the registry login's password.
type GitLabAPI struct {
	Client   *http.Client
	Endpoint string // such as https://gitlab.com
	Token    string
}

func (api GitLabAPI) query(ctx context.Context, query string, variables map[string]any, into any) error {
	body, _ := json.Marshal(map[string]any{"query": query, "variables": variables})
	authorization := ""
	if api.Token != "" {
		authorization = "Bearer " + api.Token
	}
	var answer struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if _, err := (apiCall{client: api.Client, method: http.MethodPost, url: api.Endpoint + "/api/graphql", body: body, authorization: authorization}).do(ctx, "GitLab", &answer); err != nil {
		return err
	}
	if len(answer.Errors) > 0 {
		return fmt.Errorf("GitLab's API: %s", answer.Errors[0].Message)
	}
	return json.Unmarshal(answer.Data, into)
}

// Tags lists a repository's tags, newest first, with their digests and
// when each was published. repository is the image's path, such as
// group/project or group/project/image.
func (api GitLabAPI) Tags(ctx context.Context, repository string) ([]TagInfo, error) {
	id, err := api.repositoryID(ctx, repository)
	if errors.Is(err, ErrUnauthorized) && api.Token != "" {
		// A deploy token reads the registry only; a public project needs no
		// login.
		api.Token = ""
		id, err = api.repositoryID(ctx, repository)
	}
	if err != nil {
		return nil, err
	}
	const tagsQuery = `query($id: ContainerRepositoryID!, $after: String) {
  containerRepository(id: $id) {
    tags(first: 100, after: $after, sort: PUBLISHED_AT_DESC) {
      pageInfo { hasNextPage endCursor }
      nodes { name digest publishedAt createdAt }
    }
  }
}`
	var tags []TagInfo
	after := ""
	for len(tags) < maxListed {
		variables := map[string]any{"id": id}
		if after != "" {
			variables["after"] = after
		}
		var data struct {
			ContainerRepository *struct {
				Tags struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						Name        string    `json:"name"`
						Digest      string    `json:"digest"`
						PublishedAt time.Time `json:"publishedAt"`
						CreatedAt   time.Time `json:"createdAt"`
					} `json:"nodes"`
				} `json:"tags"`
			} `json:"containerRepository"`
		}
		if err := api.query(ctx, tagsQuery, variables, &data); err != nil {
			return nil, err
		}
		if data.ContainerRepository == nil {
			return nil, fmt.Errorf("GitLab's API doesn't show %s", repository)
		}
		for _, node := range data.ContainerRepository.Tags.Nodes {
			pushed := node.PublishedAt
			if pushed.IsZero() {
				pushed = node.CreatedAt
			}
			digest := node.Digest
			if !digestPattern.MatchString(digest) {
				digest = ""
			}
			tags = append(tags, TagInfo{Tag: node.Name, Digest: digest, PushedAt: pushed.UTC()})
		}
		page := data.ContainerRepository.Tags.PageInfo
		if !page.HasNextPage || page.EndCursor == "" {
			break
		}
		after = page.EndCursor
	}
	return tags, nil
}

// repositoryID finds the container repository whose path is repository:
// its project is the longest leading part of the path that is a project.
func (api GitLabAPI) repositoryID(ctx context.Context, repository string) (string, error) {
	const projectQuery = `query($path: ID!, $name: String) {
  project(fullPath: $path) { containerRepositories(name: $name, first: 100) { nodes { id path } } }
}`
	parts := strings.Split(repository, "/")
	for end := len(parts); end >= 2; end-- {
		var data struct {
			Project *struct {
				ContainerRepositories struct {
					Nodes []struct {
						ID   string `json:"id"`
						Path string `json:"path"`
					} `json:"nodes"`
				} `json:"containerRepositories"`
			} `json:"project"`
		}
		if err := api.query(ctx, projectQuery, map[string]any{"path": strings.Join(parts[:end], "/"), "name": parts[len(parts)-1]}, &data); err != nil {
			return "", err
		}
		if data.Project == nil {
			continue
		}
		for _, node := range data.Project.ContainerRepositories.Nodes {
			if strings.EqualFold(node.Path, repository) {
				return node.ID, nil
			}
		}
		return "", fmt.Errorf("GitLab's project %s has no image %s, or the login can't see it", strings.Join(parts[:end], "/"), repository)
	}
	return "", fmt.Errorf("GitLab's API doesn't show a project for %s; it's private, and needs a login with read_api", repository)
}

// escapePath escapes each part of a slash-separated path.
func escapePath(path string) string {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
