package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWatchCountsOnlyChangesAScanSees(t *testing.T) {
	event := func(kind string, object map[string]any) string {
		data, _ := json.Marshal(map[string]any{"type": kind, "object": object})
		return string(data) + "\n"
	}
	meta := func(namespace, name string, generation int, version string, owned bool) map[string]any {
		m := map[string]any{"name": name, "namespace": namespace, "generation": generation, "resourceVersion": version}
		if owned {
			m["ownerReferences"] = []any{map[string]any{"kind": "ReplicaSet"}}
		}
		return map[string]any{"metadata": m}
	}
	streams := map[string]string{
		"/apis/apps/v1/deployments": event("MODIFIED", meta("shop", "web", 1, "11", false)) + // status only: the same generation
			event("MODIFIED", meta("shop", "web", 2, "12", false)) + // a spec change
			event("BOOKMARK", meta("", "", 0, "13", false)),
		"/api/v1/pods": event("ADDED", meta("shop", "web-abc", 1, "20", true)) + // a controller's pod
			event("MODIFIED", meta("shop", "debug", 0, "21", false)) + // a bare pod's status: already seen
			event("ADDED", meta("shop", "shell", 0, "22", false)), // a new bare pod
		"/apis/rbac.authorization.k8s.io/v1/roles": event("DELETED", meta("shop", "reader", 0, "30", false)),
	}
	lists := map[string][]map[string]any{
		"/apis/apps/v1/deployments":                {meta("shop", "web", 1, "10", false)},
		"/api/v1/pods":                             {meta("shop", "debug", 0, "19", false)},
		"/apis/rbac.authorization.k8s.io/v1/roles": {meta("shop", "reader", 0, "29", false)},
	}
	var mu sync.Mutex
	served := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "1" {
			items := lists[r.URL.Path]
			if items == nil {
				items = []map[string]any{}
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "100"}, "items": items})
			return
		}
		if r.URL.Query().Get("resourceVersion") != "100" {
			t.Errorf("watch from %s", r.URL.Query().Get("resourceVersion"))
		}
		mu.Lock()
		served[r.URL.Path]++
		first := served[r.URL.Path] == 1
		mu.Unlock()
		if stream, ok := streams[r.URL.Path]; ok && first {
			w.Write([]byte(stream))
			return
		}
		// Nothing else happens: hold the watch open, as the API does.
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := Connect(writeKubeconfig(t, server, "      token: secret"), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var changes []string
	go client.Watch(ctx, func(kind, namespace, name string) {
		mu.Lock()
		changes = append(changes, kind+" "+namespace+"/"+name)
		mu.Unlock()
	})
	time.Sleep(500 * time.Millisecond)
	cancel()
	mu.Lock()
	defer mu.Unlock()
	slices.Sort(changes)
	if want := "Deployment shop/web, Pod shop/shell, Role shop/reader"; strings.Join(changes, ", ") != want {
		t.Fatalf("changes = %v; want %s", changes, want)
	}
}
