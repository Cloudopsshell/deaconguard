package images

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHubAPI(t *testing.T) {
	var server *httptest.Server
	requests := 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch {
		case r.URL.Path == "/v2/auth/token":
			var body struct{ Identifier, Secret string }
			json.NewDecoder(r.Body).Decode(&body)
			if body.Identifier != "robot" || body.Secret != "dckr_pat_x" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "jwt"})
		case r.URL.Path == "/v2/namespaces/acme/repositories/private/tags":
			if r.Header.Get("Authorization") != "Bearer jwt" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprint(w, `{"next":null,"results":[{"name":"v2","digest":"sha256:`+strings.Repeat("2", 64)+`","tag_last_pushed":"2026-10-02T00:00:00Z"}]}`)
		case r.URL.Path == "/v2/namespaces/library/repositories/alpine/tags":
			if r.URL.Query().Get("ordering") != "last_updated" || r.URL.Query().Get("page_size") != "100" {
				t.Errorf("query %s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("page") == "2" {
				// An old tag: no push time, only last_updated, and no digest.
				fmt.Fprint(w, `{"next":"https://elsewhere.example/next","results":[{"name":"2.6","last_updated":"2016-02-02T19:50:30Z"}]}`)
				return
			}
			fmt.Fprintf(w, `{"next":"%s/v2/namespaces/library/repositories/alpine/tags?page=2&page_size=100&ordering=last_updated","results":[{"name":"3.22","digest":"sha256:%s","tag_last_pushed":"2026-10-23T05:24:47.66Z","last_updated":"2026-10-23T05:24:47.66Z"}]}`, server.URL, strings.Repeat("a", 64))
		case r.URL.Path == "/v2/namespaces/robot/repositories":
			fmt.Fprint(w, `{"next":null,"results":[{"name":"web"},{"name":"api"}]}`)
		case r.URL.Path == "/v2/namespaces/library/repositories/many/tags":
			// Docker Hub refuses anonymous pages past the first 1,000 tags.
			page := 1
			fmt.Sscan(r.URL.Query().Get("page"), &page)
			if page > 10 && r.Header.Get("Authorization") == "" || page > 12 {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"message":"pagination offset too large for anonymous requests; sign in to page further"}`)
				return
			}
			var results []string
			for i := range 100 {
				results = append(results, fmt.Sprintf(`{"name":"t%d-%d","tag_last_pushed":"2026-10-01T00:00:00Z"}`, page, i))
			}
			fmt.Fprintf(w, `{"next":"%s/v2/namespaces/library/repositories/many/tags?page=%d&page_size=100&ordering=last_updated","results":[%s]}`, server.URL, page+1, strings.Join(results, ","))
		case r.URL.Path == "/v2/namespaces/library/repositories/busy/tags":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()

	public := &HubAPI{Client: server.Client(), Endpoint: server.URL}
	tags, err := public.Tags(ctx, "library/alpine")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0].Tag != "3.22" || tags[0].Digest != "sha256:"+strings.Repeat("a", 64) || tags[0].PushedAt.Format(time.RFC3339) != "2026-10-23T05:24:47Z" {
		t.Fatalf("tags: %+v", tags)
	}
	if tags[1].Digest != "" || tags[1].PushedAt.Year() != 2016 {
		t.Fatalf("an old tag falls back to last_updated: %+v", tags[1])
	}
	if requests != 2 {
		t.Fatalf("%d requests; a next page on another host must not be followed", requests)
	}
	if _, err := public.Tags(ctx, "acme/private"); err == nil || !strings.Contains(err.Error(), "add a login for docker.io") {
		t.Fatalf("a private repository without a login: %v", err)
	}
	if _, err := public.Repositories(ctx); !errors.Is(err, ErrListingRefused) {
		t.Fatalf("listing without a login: %v", err)
	}
	if _, err := public.Tags(ctx, "library/busy"); err == nil || !strings.Contains(err.Error(), "limiting requests") {
		t.Fatalf("rate limited: %v", err)
	}

	// A busy public repository: the newest 1,000 tags, without asking for
	// pages Docker Hub refuses.
	requests = 0
	if tags, err := public.Tags(ctx, "library/many"); err != nil || len(tags) != 1000 || requests != 10 {
		t.Fatalf("anonymous paging: %d tags in %d requests, %v", len(tags), requests, err)
	}
	login := &HubAPI{Client: server.Client(), Endpoint: server.URL, Username: "robot", Secret: "dckr_pat_x"}
	// With a login it pages further, and a refused later page ends the
	// listing with the tags read.
	if tags, err := login.Tags(ctx, "library/many"); err != nil || len(tags) != 1200 {
		t.Fatalf("paging with a login: %d tags, %v", len(tags), err)
	}
	login = &HubAPI{Client: server.Client(), Endpoint: server.URL, Username: "robot", Secret: "dckr_pat_x"}
	if tags, err := login.Tags(ctx, "acme/private"); err != nil || len(tags) != 1 || tags[0].Tag != "v2" {
		t.Fatalf("a private repository with a login: %+v, %v", tags, err)
	}
	if names, err := login.Repositories(ctx); err != nil || strings.Join(names, ",") != "robot/api,robot/web" {
		t.Fatalf("the namespace's repositories: %v, %v", names, err)
	}
	wrong := &HubAPI{Client: server.Client(), Endpoint: server.URL, Username: "robot", Secret: "wrong"}
	if _, err := wrong.Tags(ctx, "library/alpine"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a wrong token: %v", err)
	}
	if _, err := public.Tags(ctx, "alpine"); err == nil {
		t.Fatal("a repository without a namespace was accepted")
	}
}

func TestGitHubPackagesAPI(t *testing.T) {
	var server *httptest.Server
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_x" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"Bad credentials"}`)
			return
		}
		if r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Errorf("no API version")
		}
		switch r.URL.EscapedPath() {
		case "/orgs/acme/packages/container/team%2Fshop/versions":
			if r.URL.Query().Get("page") == "2" {
				fmt.Fprintf(w, `[{"name":"%s","created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z","metadata":{"container":{"tags":["v1"]}}}]`, digest("1"))
				return
			}
			w.Header().Set("Link", `<`+server.URL+`/orgs/acme/packages/container/team%2Fshop/versions?per_page=100&page=2>; rel="next"`)
			fmt.Fprintf(w, `[{"name":"%s","created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z","metadata":{"container":{"tags":["v2","latest"]}}},
				{"name":"%s","created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z","metadata":{"container":{"tags":[]}}},
				{"name":"%s","created_at":"2026-08-01T00:00:00Z","updated_at":"2026-10-05T00:00:00Z","metadata":{"container":{"tags":["stable"]}}}]`, digest("2"), digest("9"), digest("0"))
		case "/orgs/someone/packages/container/tool/versions", "/user/packages/container/tool/versions":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)
		case "/users/someone/packages/container/tool/versions":
			fmt.Fprintf(w, `[{"name":"%s","created_at":"2026-10-03T00:00:00Z","updated_at":"2026-10-03T00:00:00Z","metadata":{"container":{"tags":["1.0"]}}}]`, digest("3"))
		case "/user/packages":
			fmt.Fprint(w, `[{"name":"tool","owner":{"login":"Me"}}]`)
		case "/user/orgs":
			fmt.Fprint(w, `[{"login":"acme"},{"login":"sso-locked"}]`)
		case "/orgs/acme/packages":
			fmt.Fprint(w, `[{"name":"team/shop","owner":{"login":"acme"}},{"name":"tool","owner":{"login":"me"}}]`)
		case "/orgs/sso-locked/packages":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	api := GitHubPackagesAPI{Client: server.Client(), Endpoint: server.URL, Token: "ghp_x"}

	tags, err := api.Tags(ctx, "acme/team/shop")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TagInfo{}
	for _, tag := range tags {
		got[tag.Tag] = tag
	}
	if len(tags) != 4 || got["v2"].Digest != digest("2") || got["latest"].Digest != digest("2") || got["v1"].PushedAt.Month() != 9 {
		t.Fatalf("org package over two pages, untagged versions left out: %+v", tags)
	}
	if got["stable"].PushedAt.Day() != 5 {
		t.Fatalf("a tag added later counts from then: %+v", got["stable"])
	}
	if tags, err := api.Tags(ctx, "someone/tool"); err != nil || len(tags) != 1 || tags[0].Tag != "1.0" {
		t.Fatalf("a user's package: %+v, %v", tags, err)
	}
	if _, err := api.Tags(ctx, "nobody/none"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("a missing package: %v", err)
	}
	if names, err := api.Repositories(ctx); err != nil || strings.Join(names, ",") != "acme/team/shop,me/tool" {
		t.Fatalf("repositories, an org refusing the token left out: %v, %v", names, err)
	}
	bad := api
	bad.Token = "wrong"
	if _, err := bad.Tags(ctx, "acme/team/shop"); !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), "read:packages") {
		t.Fatalf("a wrong token: %v", err)
	}
}
