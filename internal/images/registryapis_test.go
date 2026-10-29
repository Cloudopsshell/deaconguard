package images

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGoogleTagsListTimes(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team/app/tags/list" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"name":"team/app","tags":["v1","v2","bare"],"manifest":{
			"sha256:%s":{"tag":["v1"],"timeUploadedMs":"1790000000000","timeCreatedMs":"0"},
			"sha256:%s":{"tag":["v2"],"timeUploadedMs":"1791000000000"}}}`, strings.Repeat("1", 64), strings.Repeat("2", 64))
	}))
	defer server.Close()
	client, _ := testClient(server, "", "")
	tags, err := client.Tags(context.Background(), strings.TrimPrefix(server.URL, "https://"), "team/app")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TagInfo{}
	for _, tag := range tags {
		got[tag.Tag] = tag
	}
	if got["v2"].PushedAt.UnixMilli() != 1791000000000 || got["v2"].Digest != "sha256:"+strings.Repeat("2", 64) || got["v1"].PushedAt.IsZero() {
		t.Fatalf("upload times and digests from manifest: %+v", tags)
	}
	if !got["bare"].PushedAt.IsZero() || len(tags) != 3 {
		t.Fatalf("a tag without manifest data: %+v", tags)
	}
}

func TestACRTags(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if r.URL.Query().Get("scope") != "repository:team/app:metadata_read" {
				t.Errorf("scope %q", r.URL.Query().Get("scope"))
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "acr-token"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer acr-token" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/oauth2/token",service="fake.azurecr.io",scope="repository:team/app:metadata_read"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/acr/v1/team/app/_tags" || r.URL.Query().Get("orderby") != "timedesc" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</acr/v1/team/app/_tags?last=v2&n=100&orderby=timedesc>; rel="next"`)
			fmt.Fprintf(w, `{"tags":[{"name":"v2","digest":"sha256:%s","createdTime":"2026-10-01T00:00:00Z","lastUpdateTime":"2026-10-02T00:00:00Z"}]}`, strings.Repeat("2", 64))
			return
		}
		fmt.Fprint(w, `{"tags":[{"name":"v1","digest":"bad","createdTime":"2026-09-01T00:00:00Z"}]}`)
	}))
	defer server.Close()
	client, _ := testClient(server, "robot", "pw")
	tags, err := client.ACRTags(context.Background(), strings.TrimPrefix(server.URL, "https://"), "team/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0].PushedAt.Day() != 2 || tags[0].Digest == "" || tags[1].Digest != "" || tags[1].PushedAt.Month() != 9 {
		t.Fatalf("ACR tags over two pages: %+v", tags)
	}
	for _, host := range []string{"acme.azurecr.io", "acme.azurecr.cn:443"} {
		if !IsACR(host) {
			t.Errorf("%s is ACR", host)
		}
	}
	if IsACR("azurecr.io.example.com") {
		t.Error("a look-alike host is not ACR")
	}
}

func TestQuayAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/discovery" {
			fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Quay Frontend"}}`)
			return
		}
		if r.URL.Path != "/api/v1/repository/team/app/tag/" || r.URL.Query().Get("onlyActiveTags") != "true" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("page") == "1" {
			fmt.Fprintf(w, `{"tags":[{"name":"v2","manifest_digest":"sha256:%s","start_ts":1791000000}],"has_additional":true,"page":1}`, strings.Repeat("2", 64))
			return
		}
		if r.Header.Get("Authorization") == "Bearer wrong" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"tags":[{"name":"v1","start_ts":1790000000}],"has_additional":false,"page":2}`)
	}))
	defer server.Close()
	ctx := context.Background()
	flavor, endpoint := DetectFlavor(ctx, server.Client(), "http", strings.TrimPrefix(server.URL, "http://"))
	if flavor != FlavorQuay || endpoint != server.URL {
		t.Fatalf("detected %q at %s", flavor, endpoint)
	}
	tags, err := QuayAPI{Client: server.Client(), Endpoint: endpoint}.Tags(ctx, "team/app")
	if err != nil || len(tags) != 2 || tags[0].PushedAt.Unix() != 1791000000 || tags[0].Digest == "" || tags[1].Tag != "v1" {
		t.Fatalf("tags over two pages: %+v, %v", tags, err)
	}
	if _, err := (QuayAPI{Client: server.Client(), Endpoint: endpoint, Token: "wrong"}).Tags(ctx, "team/app"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a wrong token: %v", err)
	}
}

func TestHarborAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/systeminfo" {
			fmt.Fprint(w, `{"auth_mode":"db_auth","primary_auth_mode":false}`)
			return
		}
		user, pass, ok := r.BasicAuth()
		if ok && (user != "robot$ci" || pass != "secret") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.EscapedPath() {
		case "/api/v2.0/projects/team/repositories/apps%252Fweb/artifacts":
			if r.URL.Query().Get("with_tag") != "true" {
				t.Errorf("query %s", r.URL.RawQuery)
			}
			fmt.Fprintf(w, `[{"digest":"sha256:%s","push_time":"2026-10-01T00:00:00Z","tags":[{"name":"v2","push_time":"2026-10-03T00:00:00Z"},{"name":"latest"}]},
				{"digest":"sha256:%s","push_time":"2026-09-01T00:00:00Z","tags":null}]`, strings.Repeat("2", 64), strings.Repeat("0", 64))
		case "/api/v2.0/repositories":
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `[{"name":"team/apps/web"},{"name":"library/base"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	flavor, endpoint := DetectFlavor(ctx, server.Client(), "http", strings.TrimPrefix(server.URL, "http://"))
	if flavor != FlavorHarbor {
		t.Fatalf("detected %q", flavor)
	}
	public := HarborAPI{Client: server.Client(), Endpoint: endpoint}
	tags, err := public.Tags(ctx, "team/apps/web")
	if err != nil || len(tags) != 2 || tags[0].Tag != "v2" || tags[0].PushedAt.Day() != 3 || tags[1].PushedAt.Day() != 1 || tags[1].Digest == "" {
		t.Fatalf("tags: %+v, %v", tags, err)
	}
	if _, err := public.Repositories(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("repositories without a login: %v", err)
	}
	robot := HarborAPI{Client: server.Client(), Endpoint: endpoint, Username: "robot$ci", Password: "secret"}
	if names, err := robot.Repositories(ctx); err != nil || strings.Join(names, ",") != "library/base,team/apps/web" {
		t.Fatalf("repositories: %v, %v", names, err)
	}
	if _, err := public.Tags(ctx, "lonely"); err == nil {
		t.Fatal("a name without a project was accepted")
	}
}

func TestGitLabAPI(t *testing.T) {
	queries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/graphql" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") == "Bearer deploy-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		queries++
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		json.Unmarshal(body, &request)
		switch {
		case strings.Contains(request.Query, "__typename"):
			fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
		case strings.Contains(request.Query, "project(fullPath"):
			switch request.Variables["path"] {
			case "group/project/image":
				fmt.Fprint(w, `{"data":{"project":null}}`)
			case "group/project":
				fmt.Fprint(w, `{"data":{"project":{"containerRepositories":{"nodes":[{"id":"gid://gitlab/ContainerRepository/1","path":"group/project/image-dev"},{"id":"gid://gitlab/ContainerRepository/2","path":"group/project/image"}]}}}}`)
			default:
				fmt.Fprint(w, `{"data":{"project":null}}`)
			}
		case strings.Contains(request.Query, "containerRepository(id"):
			if request.Variables["id"] != "gid://gitlab/ContainerRepository/2" {
				t.Errorf("id %v", request.Variables["id"])
			}
			if request.Variables["after"] == nil {
				fmt.Fprintf(w, `{"data":{"containerRepository":{"tags":{"pageInfo":{"hasNextPage":true,"endCursor":"c1"},"nodes":[{"name":"main-0aaa","digest":"sha256:%s","publishedAt":"2026-10-02T00:00:00+00:00","createdAt":"2026-10-01T00:00:00+00:00"}]}}}}`, strings.Repeat("a", 64))
				return
			}
			fmt.Fprint(w, `{"data":{"containerRepository":{"tags":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"name":"main-ffff","createdAt":"2026-09-01T00:00:00+00:00"}]}}}}`)
		default:
			fmt.Fprint(w, `{"errors":[{"message":"unexpected query"}]}`)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	host := strings.TrimPrefix(server.URL, "http://")
	// The test server's address has no gitlab in its name: it isn't asked.
	if flavor, _ := DetectFlavor(ctx, server.Client(), "http", host); flavor != FlavorNone {
		t.Fatalf("detected %q on a host not named for GitLab", flavor)
	}
	if hosts := gitLabHosts("registry.gitlab.example.com"); len(hosts) != 1 || hosts[0] != "gitlab.example.com" {
		t.Fatalf("hosts %v", hosts)
	}
	if hosts := gitLabHosts("gitlab.example.com:5050"); len(hosts) != 1 || hosts[0] != "gitlab.example.com" {
		t.Fatalf("hosts %v", hosts)
	}
	if hosts := gitLabHosts("registry.example.com"); len(hosts) != 0 {
		t.Fatalf("a host not named for GitLab: %v", hosts)
	}

	// A deploy token can't read the API: the public project is read without it.
	api := GitLabAPI{Client: server.Client(), Endpoint: server.URL, Token: "deploy-token"}
	tags, err := api.Tags(ctx, "group/project/image")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0].Tag != "main-0aaa" || tags[0].PushedAt.Day() != 2 || tags[0].Digest == "" || tags[1].PushedAt.Month() != 9 {
		t.Fatalf("tags over two pages, the exact image path among similar ones: %+v", tags)
	}
	if _, err := api.Tags(ctx, "other/thing"); err == nil || !strings.Contains(err.Error(), "read_api") {
		t.Fatalf("an unknown project: %v", err)
	}
}
