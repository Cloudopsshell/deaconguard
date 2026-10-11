package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

// signInAs creates an account with role and signs it in.
func signInAs(t *testing.T, s *Server, username, role string) *http.Cookie {
	t.Helper()
	if _, err := store.AddUser(username, []byte(testPassword), role, false); err != nil {
		t.Fatal(err)
	}
	cookie, body, code := login(t, s, username, testPassword)
	if code != http.StatusOK || body.Role != role {
		t.Fatalf("sign in as %s: %d %+v", role, code, body)
	}
	return cookie
}

func TestRolesLimitWhatAccountsCanDo(t *testing.T) {
	s := newNetworkTestServer(t)
	admin := signIn(t, s)
	operator := signInAs(t, s, "olivia", store.RoleOperator)
	viewer := signInAs(t, s, "victor", store.RoleViewer)

	// Each route with the least role it needs; the host and scan IDs don't
	// exist, so an allowed request fails later, but never with 403.
	routes := []struct {
		method, path, needs string
		body                any
	}{
		{http.MethodGet, "/api/hosts", store.RoleViewer, nil},
		{http.MethodGet, "/api/summary", store.RoleViewer, nil},
		{http.MethodGet, "/api/schedules", store.RoleViewer, nil},
		{http.MethodGet, "/api/logs", store.RoleViewer, nil},
		{http.MethodGet, "/api/account", store.RoleViewer, nil},
		{http.MethodPost, "/api/hosts/nope/scans", store.RoleOperator, map[string]any{}},
		{http.MethodDelete, "/api/scans/nope", store.RoleOperator, nil},
		{http.MethodPatch, "/api/hosts/nope", store.RoleOperator, map[string]any{"allow_sudo": true}},
		{http.MethodPost, "/api/schedules", store.RoleOperator, map[string]any{}},
		{http.MethodGet, "/api/logs/download", store.RoleOperator, nil},
		{http.MethodDelete, "/api/hosts/nope", store.RoleAdmin, nil},
		{http.MethodGet, "/api/enrollment-tokens", store.RoleAdmin, nil},
		{http.MethodPost, "/api/enrollment-tokens", store.RoleAdmin, map[string]any{}},
		{http.MethodGet, "/api/users", store.RoleAdmin, nil},
		{http.MethodGet, "/api/audit", store.RoleAdmin, nil},
		{http.MethodPatch, "/api/settings/security", store.RoleAdmin, map[string]any{"require_mfa": false}},
	}
	accounts := []struct {
		role   string
		cookie *http.Cookie
	}{{store.RoleViewer, viewer}, {store.RoleOperator, operator}, {store.RoleAdmin, admin}}
	for _, route := range routes {
		for _, account := range accounts {
			response := do(t, s, call{method: route.method, path: route.path, body: route.body, cookie: account.cookie})
			allowed := store.RoleAllows(account.role, route.needs)
			if forbidden := response.Code == http.StatusForbidden; forbidden == allowed {
				t.Errorf("%s %s as %s: %d %s", route.method, route.path, account.role, response.Code, response.Body.String())
			}
		}
	}
}

func TestRolesCanBeChangedButOneAdminStays(t *testing.T) {
	s := newNetworkTestServer(t)
	admin := signIn(t, s)

	// New accounts made on the dashboard are viewers unless told otherwise.
	created := do(t, s, call{method: http.MethodPost, path: "/api/users", body: map[string]string{"username": "nina", "password": testPassword}, cookie: admin})
	nina := decode[store.User](t, created)
	if created.Code != http.StatusCreated || nina.Role != store.RoleViewer {
		t.Fatalf("create: %d %+v", created.Code, nina)
	}
	if bad := do(t, s, call{method: http.MethodPost, path: "/api/users", body: map[string]string{"username": "x", "password": testPassword, "role": "root"}, cookie: admin}); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown role: %d", bad.Code)
	}

	// Nina chooses her own password, as the dashboard makes her at first sign-in.
	if err := store.ChangePassword(nina.ID, []byte(testPassword), "", false); err != nil {
		t.Fatal(err)
	}
	// A role change signs the account out, so the new role applies at once.
	ninaCookie, _, _ := login(t, s, "nina", testPassword)
	changed := do(t, s, call{method: http.MethodPatch, path: "/api/users/" + nina.ID, body: map[string]string{"role": store.RoleAdmin}, cookie: admin})
	if changed.Code != http.StatusOK || decode[store.User](t, changed).Role != store.RoleAdmin {
		t.Fatalf("promote: %d %s", changed.Code, changed.Body.String())
	}
	if gone := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: ninaCookie}); gone.Code != http.StatusUnauthorized {
		t.Fatalf("session after a role change: %d", gone.Code)
	}

	// Nina, now an admin, demotes the original admin; she is then the last
	// admin, and can't be demoted, disabled or removed.
	ninaCookie, _, _ = login(t, s, "nina", testPassword)
	if demoted := do(t, s, call{method: http.MethodPatch, path: "/api/users/" + adminID(t), body: map[string]string{"role": store.RoleOperator}, cookie: ninaCookie}); demoted.Code != http.StatusOK {
		t.Fatalf("demote admin: %d %s", demoted.Code, demoted.Body.String())
	}
	if err := store.SetRole(nina.ID, store.RoleViewer); err != store.ErrLastAccount {
		t.Fatalf("demote the last admin: %v", err)
	}
	if err := store.SetDisabled(nina.ID, true); err != store.ErrLastAccount {
		t.Fatalf("disable the last admin: %v", err)
	}
	if err := store.RemoveUserID(nina.ID); err != store.ErrLastAccount {
		t.Fatalf("remove the last admin: %v", err)
	}
	// Operators and viewers can still be disabled and removed.
	if err := store.SetDisabled(adminID(t), true); err != nil {
		t.Fatalf("disable an operator: %v", err)
	}
}

func TestAppearanceIsSavedPerAccount(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	if session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie})); session.Appearance != nil {
		t.Fatalf("appearance before choosing: %s", session.Appearance)
	}
	if bad := do(t, s, call{method: http.MethodPatch, path: "/api/account/appearance", body: map[string]string{"mode": "dark", "theme": "neon"}, cookie: cookie}); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown theme: %d", bad.Code)
	}
	if saved := do(t, s, call{method: http.MethodPatch, path: "/api/account/appearance", body: map[string]string{"mode": "dark", "theme": "teal"}, cookie: cookie}); saved.Code != http.StatusOK {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie}))
	if string(session.Appearance) != `{"mode":"dark","theme":"teal"}` {
		t.Fatalf("appearance after saving: %s", session.Appearance)
	}
}

func TestAgentPortServesOnlyAgents(t *testing.T) {
	s := newNetworkTestServer(t)
	agents := s.AgentHandler()
	for _, path := range []string{"/", "/login", "/api/session", "/api/hosts"} {
		recorder := httptest.NewRecorder()
		agents.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, testOrigin+path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s on the agent port: %d", path, recorder.Code)
		}
	}
	// Enrolling with a bad token reaches the agent API, which refuses it.
	recorder := httptest.NewRecorder()
	agents.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, testOrigin+agentapi.PathPrefix+"enroll", nil))
	if recorder.Code == http.StatusNotFound {
		t.Fatalf("enroll on the agent port: %d", recorder.Code)
	}
	s.SetAgentPort("8444")
	cookie := signIn(t, s)
	if capabilities := decode[capabilitiesResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/capabilities", cookie: cookie})); capabilities.AgentPort != "8444" {
		t.Fatalf("capabilities: %+v", capabilities)
	}
}
