package server

import (
	"net/http"
	"testing"

	"deaconguard/internal/store"
)

func TestTagsAndTrendsAPI(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	host, err := store.AddLocalHost("web-01", "root")
	if err != nil {
		t.Fatal(err)
	}
	set := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + host.ID + "/tags", body: map[string]any{"tags": []string{"Prod", "team:web"}}, cookie: cookie})
	if set.Code != http.StatusOK || decode[tagsRequest](t, set).Tags[0] != "prod" {
		t.Fatalf("set tags: %d %s", set.Code, set.Body.String())
	}
	if bad := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + host.ID + "/tags", body: map[string]any{"tags": []string{"no spaces"}}, cookie: cookie}); bad.Code != http.StatusBadRequest {
		t.Fatalf("bad tag: %d", bad.Code)
	}
	if missing := do(t, s, call{method: http.MethodPut, path: "/api/hosts/nope/tags", body: map[string]any{"tags": []string{}}, cookie: cookie}); missing.Code != http.StatusNotFound {
		t.Fatalf("missing host: %d", missing.Code)
	}
	tags := decode[[]store.TagCount](t, do(t, s, call{method: http.MethodGet, path: "/api/tags", cookie: cookie}))
	if len(tags) != 2 || tags[0].Tag != "prod" || tags[0].Hosts != 1 {
		t.Fatalf("tags: %+v", tags)
	}
	hosts := decode[[]store.HostSummary](t, do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: cookie}))
	if len(hosts) != 1 || len(hosts[0].Tags) != 2 {
		t.Fatalf("hosts: %+v", hosts)
	}
	points := decode[[]store.TrendPoint](t, do(t, s, call{method: http.MethodGet, path: "/api/trends?days=30&tag=prod", cookie: cookie}))
	if len(points) != 30 {
		t.Fatalf("trend points: %d", len(points))
	}
	for _, bad := range []string{"?days=0", "?days=400", "?days=x"} {
		if response := do(t, s, call{method: http.MethodGet, path: "/api/trends" + bad, cookie: cookie}); response.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, response.Code)
		}
	}
}
