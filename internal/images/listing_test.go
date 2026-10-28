package images

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistryListing(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if user, pass, _ := req.BasicAuth(); user != "robot" || pass != "pw" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case req.URL.Path == "/v2/_catalog" && req.URL.Query().Get("last") == "":
			w.Header().Set("Link", `</v2/_catalog?n=1000&last=b>; rel="next"`)
			json.NewEncoder(w).Encode(map[string][]string{"repositories": {"team/web", "team/api"}})
		case req.URL.Path == "/v2/_catalog":
			json.NewEncoder(w).Encode(map[string][]string{"repositories": {"team/db"}})
		case req.URL.Path == "/v2/team/web/tags/list" && req.URL.Query().Get("last") == "":
			w.Header().Set("Link", `<https://elsewhere.example/v2/team/web/tags/list?last=x>; rel="next"`)
			json.NewEncoder(w).Encode(map[string]any{"name": "team/web", "tags": []string{"v1.9", "v1.10"}})
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	registry := strings.TrimPrefix(server.URL, "https://")
	client := &Client{HTTP: server.Client(), Scheme: "https", Credentials: func(string) (Credentials, bool) { return Credentials{Username: "robot", Password: "pw"}, true }}
	repositories, err := client.Repositories(context.Background(), registry)
	if err != nil || strings.Join(repositories, ",") != "team/api,team/db,team/web" {
		t.Fatalf("repositories %v, %v", repositories, err)
	}
	// A next page on another host isn't followed.
	tags, err := client.Tags(context.Background(), registry, "team/web")
	if err != nil || len(tags) != 2 {
		t.Fatalf("tags %v, %v", tags, err)
	}
	wrong := &Client{HTTP: server.Client(), Scheme: "https", Credentials: func(string) (Credentials, bool) { return Credentials{Username: "robot", Password: "no"}, true }}
	if _, err := wrong.Repositories(context.Background(), registry); !errors.Is(err, ErrListingRefused) {
		t.Fatalf("a refused catalog: %v", err)
	}
}

func TestMatchTags(t *testing.T) {
	day := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tags := []TagInfo{{Tag: "v1.9.0"}, {Tag: "v1.10.0"}, {Tag: "main-abc"}, {Tag: "v1.2.0"}, {Tag: "latest"}}
	matched, err := MatchTags(tags, `^v\d+\.\d+\.\d+$`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tag := range matched {
		names = append(names, tag.Tag)
	}
	if strings.Join(names, ",") != "v1.10.0,v1.9.0,v1.2.0" {
		t.Fatalf("natural order: %v", names)
	}
	// Push times, where the registry gives them, come first.
	pushed := []TagInfo{{Tag: "v2", PushedAt: day}, {Tag: "v1", PushedAt: day.Add(time.Hour)}}
	if matched, _ := MatchTags(pushed, ""); matched[0].Tag != "v1" {
		t.Fatalf("by push time: %v", matched)
	}
	if _, err := MatchTags(tags, "("); err == nil {
		t.Fatal("a broken pattern was accepted")
	}
	if all, _ := MatchTags(tags, ""); len(all) != len(tags) {
		t.Fatalf("an empty pattern: %v", all)
	}
}

func TestECRAPI(t *testing.T) {
	var actions []string
	aws := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonEC2ContainerRegistry_V20150921.")
		actions = append(actions, action)
		var request map[string]any
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &request)
		if request["registryId"] != "123456789012" {
			t.Errorf("%s: registryId %v", action, request["registryId"])
		}
		switch action {
		case "DescribeRepositories":
			if request["nextToken"] == nil {
				json.NewEncoder(w).Encode(map[string]any{"repositories": []map[string]string{{"repositoryName": "web"}}, "nextToken": "page2"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"repositories": []map[string]string{{"repositoryName": "api"}}})
		case "DescribeImages":
			json.NewEncoder(w).Encode(map[string]any{"imageDetails": []map[string]any{
				{"imageDigest": "sha256:aa", "imageTags": []string{"v1", "stable"}, "imagePushedAt": 1790000000.5},
				{"imageDigest": "sha256:bb", "imageTags": []string{"v2"}, "imagePushedAt": 1790003600},
			}})
		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": "AccessDeniedException", "message": "no"})
		}
	}))
	defer aws.Close()
	api := ECRAPI{Client: aws.Client(), Registry: "123456789012.dkr.ecr.eu-north-1.amazonaws.com", Endpoint: aws.URL, KeyID: "AKID", Secret: "s"}
	repositories, err := api.Repositories(context.Background())
	if err != nil || strings.Join(repositories, ",") != "api,web" {
		t.Fatalf("repositories %v, %v", repositories, err)
	}
	tags, err := api.Tags(context.Background(), "web")
	if err != nil || len(tags) != 3 || tags[2].Tag != "v2" || tags[2].Digest != "sha256:bb" || tags[2].PushedAt.Unix() != 1790003600 {
		t.Fatalf("tags %+v, %v", tags, err)
	}
	if matched, _ := MatchTags(tags, "^v"); matched[0].Tag != "v2" {
		t.Fatalf("newest first: %+v", matched)
	}
	if err := api.call(context.Background(), "ListImages", map[string]any{"registryId": "123456789012"}, &struct{}{}); err == nil || !strings.Contains(err.Error(), "AccessDeniedException") || !strings.Contains(err.Error(), "ListImages") {
		t.Fatalf("a refused action: %v", err)
	}
}
