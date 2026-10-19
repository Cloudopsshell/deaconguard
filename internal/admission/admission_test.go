package admission

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reviewOf(object map[string]any) []byte {
	raw, _ := json.Marshal(object)
	body, _ := json.Marshal(map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": map[string]any{
		"uid": "abc-123", "namespace": "shop", "kind": map[string]any{"group": "apps", "version": "v1", "kind": object["kind"]}, "object": json.RawMessage(raw),
	}})
	return body
}

func deployment(annotations map[string]any) map[string]any {
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "web", "annotations": annotations},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"hostPID": true, "containers": []any{
			map[string]any{"name": "web", "image": "nginx", "securityContext": map[string]any{"privileged": true}}}}}}}
}

func answer(t *testing.T, handler http.Handler, body []byte) (bool, string, []string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
	var out struct {
		Response struct {
			UID      string   `json:"uid"`
			Allowed  bool     `json:"allowed"`
			Warnings []string `json:"warnings"`
		} `json:"response"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("answer: %d %s", recorder.Code, recorder.Body.String())
	}
	return out.Response.Allowed, out.Response.UID, out.Response.Warnings
}

func TestWarnsButNeverBlocks(t *testing.T) {
	handler := Handler("high", nil)
	allowed, uid, warnings := answer(t, handler, reviewOf(deployment(nil)))
	if !allowed || uid != "abc-123" || len(warnings) != 2 {
		t.Fatalf("allowed %v, uid %s, warnings %v", allowed, uid, warnings)
	}
	if warnings[0] != "DeaconGuard DG-K8S-001 critical: Deployment shop/web: container web is privileged" || !strings.Contains(warnings[1], "hostPID") {
		t.Fatalf("warnings: %v", warnings)
	}
	// Medium adds the unpinned image and running as root.
	if _, _, medium := answer(t, Handler("medium", nil), reviewOf(deployment(nil))); len(medium) <= len(warnings) {
		t.Fatalf("medium: %v", medium)
	}
	// The ignore annotation is honoured.
	if _, _, none := answer(t, handler, reviewOf(deployment(map[string]any{"deaconguard.io/ignore": "DG-K8S-001, DG-K8S-002"}))); len(none) != 0 {
		t.Fatalf("ignored: %v", none)
	}
	// A controller's pod was checked through the controller.
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "web-1", "ownerReferences": []any{map[string]any{"kind": "ReplicaSet"}}},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "web", "image": "nginx", "securityContext": map[string]any{"privileged": true}}}}}
	if allowed, _, owned := answer(t, handler, reviewOf(pod)); !allowed || len(owned) != 0 {
		t.Fatalf("an owned pod: %v %v", allowed, owned)
	}
	// Not a review: refused, not crashed.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{}")))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("not a review: %d", recorder.Code)
	}
}
