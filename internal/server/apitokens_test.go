package server

import (
	"net/http"
	"strings"
	"testing"

	"deaconguard/internal/store"
)

func TestAPITokens(t *testing.T) {
	s := newNetworkTestServer(t)
	admin := signIn(t, s)
	create := func(cookie *http.Cookie, body map[string]any) (int, createdAPIToken) {
		response := do(t, s, call{method: http.MethodPost, path: "/api/account/tokens", body: body, cookie: cookie})
		if response.Code != http.StatusCreated {
			return response.Code, createdAPIToken{}
		}
		return response.Code, decode[createdAPIToken](t, response)
	}
	_, viewerToken := create(admin, map[string]any{"name": "dashboard screen", "role": "viewer", "days": 30})
	if !strings.HasPrefix(viewerToken.Token, store.APITokenPrefix) || viewerToken.ExpiresAt == "" {
		t.Fatalf("token: %+v", viewerToken)
	}
	_, ci := create(admin, map[string]any{"name": "ci", "role": "operator", "days": 0})
	if ci.ExpiresAt != "" {
		t.Fatalf("a token until revoked has no expiry: %+v", ci)
	}
	for _, bad := range []map[string]any{{"name": "", "role": "viewer"}, {"name": "x", "role": "root"}, {"name": "x", "role": "viewer", "days": 400}} {
		if code, _ := create(admin, bad); code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, code)
		}
	}
	host, _ := store.AddLocalHost("web-01", "root")

	// A viewer token reads but can't change anything.
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts", bearer: viewerToken.Token}); response.Code != http.StatusOK {
		t.Fatalf("viewer token reading hosts: %d %s", response.Code, response.Body.String())
	}
	if response := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + host.ID + "/tags", body: map[string]any{"tags": []string{"x"}}, bearer: viewerToken.Token}); response.Code != http.StatusForbidden {
		t.Fatalf("viewer token changing tags: %d", response.Code)
	}
	// An operator token can.
	if response := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + host.ID + "/tags", body: map[string]any{"tags": []string{"ci"}}, bearer: ci.Token}); response.Code != http.StatusOK {
		t.Fatalf("operator token changing tags: %d %s", response.Code, response.Body.String())
	}
	// No token reaches accounts, tokens or sign-in.
	for _, path := range []string{"/api/account/tokens", "/api/users", "/api/tokens", "/api/account", "/api/session"} {
		if response := do(t, s, call{method: http.MethodGet, path: path, bearer: ci.Token}); response.Code != http.StatusForbidden && path != "/api/session" {
			t.Errorf("%s with a token: %d", path, response.Code)
		}
	}
	if response := do(t, s, call{method: http.MethodPost, path: "/api/account/tokens", body: map[string]any{"name": "more", "role": "operator"}, bearer: ci.Token}); response.Code != http.StatusForbidden {
		t.Fatalf("a token made a token: %d", response.Code)
	}
	// The audit log names the token.
	entries := decode[[]store.AuditEntry](t, do(t, s, call{method: http.MethodGet, path: "/api/audit", cookie: admin}))
	found := false
	for _, entry := range entries {
		if entry.Action == "host.tags" && entry.Actor == "admin (API token ci)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit log: %+v", entries[:3])
	}

	// A token never has more than its account: demote the account, and its
	// operator token reads only.
	operator, _ := store.AddUser("olivia", []byte(testPassword), store.RoleOperator, false)
	cookie, _, _ := login(t, s, "olivia", testPassword)
	if code, _ := create(cookie, map[string]any{"name": "too much", "role": "admin"}); code != http.StatusBadRequest {
		t.Fatalf("an operator made an admin token: %d", code)
	}
	_, hers := create(cookie, map[string]any{"name": "hers", "role": "operator"})
	if err := store.SetRole(operator.ID, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if response := do(t, s, call{method: http.MethodPut, path: "/api/hosts/" + host.ID + "/tags", body: map[string]any{"tags": []string{"y"}}, bearer: hers.Token}); response.Code != http.StatusForbidden {
		t.Fatalf("a demoted account's token kept its role: %d", response.Code)
	}
	if err := store.SetDisabled(operator.ID, true); err != nil {
		t.Fatal(err)
	}
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts", bearer: hers.Token}); response.Code != http.StatusUnauthorized {
		t.Fatalf("a disabled account's token: %d", response.Code)
	}

	// Revoked tokens stop at once; others list them as revoked.
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/account/tokens/" + viewerToken.ID, cookie: admin}); response.Code != http.StatusOK {
		t.Fatalf("revoke: %d", response.Code)
	}
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts", bearer: viewerToken.Token}); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", response.Code)
	}
	listed := decode[[]store.APIToken](t, do(t, s, call{method: http.MethodGet, path: "/api/account/tokens", cookie: admin}))
	if len(listed) != 2 || listed[1].Status != "revoked" || listed[0].LastUsedAt == "" {
		t.Fatalf("tokens: %+v", listed)
	}
	// Someone else's token can't be revoked through My account, only by an admin.
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/account/tokens/" + ci.ID, cookie: cookie}); response.Code == http.StatusOK {
		t.Fatal("revoked another account's token")
	}
	if all := decode[[]store.APIToken](t, do(t, s, call{method: http.MethodGet, path: "/api/tokens", cookie: admin})); len(all) != 3 {
		t.Fatalf("admin list: %d", len(all))
	}

	// Guessing is limited.
	for attempt := 0; attempt < maxFailures; attempt++ {
		do(t, s, call{method: http.MethodGet, path: "/api/hosts", bearer: store.APITokenPrefix + "guess"})
	}
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts", bearer: ci.Token}); response.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong tokens: %d", maxFailures, response.Code)
	}
}
