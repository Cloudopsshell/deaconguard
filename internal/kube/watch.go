package kube

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/buildinfo"
)

// watched are the objects whose changes matter to a cluster scan.
var watched = []struct{ kind, path string }{
	{"Deployment", "/apis/apps/v1/deployments"},
	{"StatefulSet", "/apis/apps/v1/statefulsets"},
	{"DaemonSet", "/apis/apps/v1/daemonsets"},
	{"CronJob", "/apis/batch/v1/cronjobs"},
	{"Pod", "/api/v1/pods"},
	{"Namespace", "/api/v1/namespaces"},
	{"NetworkPolicy", "/apis/networking.k8s.io/v1/networkpolicies"},
	{"ClusterRole", "/apis/rbac.authorization.k8s.io/v1/clusterroles"},
	{"ClusterRoleBinding", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
	{"Role", "/apis/rbac.authorization.k8s.io/v1/roles"},
	{"RoleBinding", "/apis/rbac.authorization.k8s.io/v1/rolebindings"},
}

// watchedMeta is what a change is judged by.
type watchedMeta struct {
	Metadata struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
		Generation      int64  `json:"generation"`
		OwnerReferences []any  `json:"ownerReferences"`
	} `json:"metadata"`
}

// fingerprint is what changes when an object changes in a way a scan
// would see: its generation, which counts spec changes, where it has one,
// so status updates don't count; otherwise its resource version. A pod's
// spec hardly changes, and its status always does: only a new pod counts.
func (m watchedMeta) fingerprint(kind string) string {
	if kind == "Pod" {
		return "pod"
	}
	if m.Metadata.Generation > 0 {
		return "g" + strconv.FormatInt(m.Metadata.Generation, 10)
	}
	return "r" + m.Metadata.ResourceVersion
}

// Watch follows the cluster's workloads, roles, namespaces and network
// policies, and calls changed with each change a scan would see: a spec
// change, a new or deleted object, a changed role or namespace, a pod no
// controller owns. Status updates don't count. It runs until ctx ends,
// watching again after errors.
func (c *Client) Watch(ctx context.Context, changed func(kind, namespace, name string)) {
	var wg sync.WaitGroup
	for _, w := range watched {
		wg.Add(1)
		go func(kind, path string) {
			defer wg.Done()
			c.watchKind(ctx, kind, path, changed)
		}(w.kind, w.path)
	}
	wg.Wait()
}

func (c *Client) watchKind(ctx context.Context, kind, path string, changed func(kind, namespace, name string)) {
	seen := map[string]string{}
	backoff := time.Second
	for ctx.Err() == nil {
		version, err := c.baseline(ctx, path, kind, seen)
		if err == nil {
			err = c.follow(ctx, path, kind, version, seen, changed)
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrForbidden) {
			// The account may not watch this kind: the scan notes it.
			return
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, time.Minute)
			continue
		}
		backoff = time.Second
	}
}

// baseline lists the kind, records each object, and returns the list's
// resource version to watch from. Objects that changed while the watch was
// down count as changes, except on the first list.
func (c *Client) baseline(ctx context.Context, path, kind string, seen map[string]string) (string, error) {
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []watchedMeta `json:"items"`
	}
	if err := c.Get(ctx, path, &list); err != nil {
		return "", err
	}
	for _, item := range list.Items {
		seen[item.Metadata.Namespace+"/"+item.Metadata.Name] = item.fingerprint(kind)
	}
	return list.Metadata.ResourceVersion, nil
}

// follow reads a watch stream until it ends.
func (c *Client) follow(ctx context.Context, path, kind, version string, seen map[string]string, changed func(kind, namespace, name string)) error {
	query := url.Values{"watch": {"1"}, "resourceVersion": {version}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {"300"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+path+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	if c.token != nil {
		token, err := c.token(ctx)
		if err != nil {
			return err
		}
		if strings.HasPrefix(token, "Basic ") {
			request.Header.Set("Authorization", token)
		} else if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
	}
	// A watch stays open for minutes: no overall timeout, only the context.
	response, err := (&http.Client{Transport: c.http.Transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return fmt.Errorf("%s: %w", path, ErrForbidden)
	default:
		return fmt.Errorf("watch %s: %s", path, response.Status)
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for scanner.Scan() {
		var event struct {
			Type   string          `json:"type"`
			Object json.RawMessage `json:"object"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		var meta watchedMeta
		if err := json.Unmarshal(event.Object, &meta); err != nil {
			continue
		}
		key := meta.Metadata.Namespace + "/" + meta.Metadata.Name
		switch event.Type {
		case "ERROR":
			// Usually 410 Gone: the version is too old; list again.
			return errors.New("the watch expired")
		case "BOOKMARK":
			continue
		case "DELETED":
			delete(seen, key)
			if kind != "Pod" || len(meta.Metadata.OwnerReferences) == 0 {
				changed(kind, meta.Metadata.Namespace, meta.Metadata.Name)
			}
		case "ADDED", "MODIFIED":
			// A controller's pods come and go with every rollout; its
			// own change is what counts.
			if kind == "Pod" && len(meta.Metadata.OwnerReferences) > 0 {
				continue
			}
			fingerprint := meta.fingerprint(kind)
			if seen[key] == fingerprint {
				continue
			}
			seen[key] = fingerprint
			changed(kind, meta.Metadata.Namespace, meta.Metadata.Name)
		}
	}
	return scanner.Err()
}
