package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"deaconguard/internal/oidc/oidctest"
	"deaconguard/internal/store"
)

// ssoSignIn runs a sign-in through the test provider, as the browser would,
// and returns where the dashboard sent the browser and the session cookie.
func ssoSignIn(t *testing.T, s *Server, idp *oidctest.Provider, mangle func(state string) (string, string)) (string, *http.Cookie) {
	t.Helper()
	start := do(t, s, call{method: http.MethodGet, path: "/api/login/sso?next=/hosts"})
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Header().Get("Location"))
	}
	var stateCookie *http.Cookie
	for _, cookie := range start.Result().Cookies() {
		if cookie.Name == ssoCookie {
			stateCookie = cookie
		}
	}
	if stateCookie == nil || stateCookie.SameSite != http.SameSiteLaxMode || !stateCookie.HttpOnly || !stateCookie.Secure {
		t.Fatalf("state cookie: %+v", stateCookie)
	}
	client := idp.Server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	back, _ := url.Parse(response.Header.Get("Location"))
	if back.Host != "deaconguard.example:8443" || back.Path != ssoCallbackPath {
		t.Fatalf("the provider sent the browser to %s", back)
	}
	query := back.Query()
	cookieValue, state := stateCookie.Value, query.Get("state")
	if mangle != nil {
		cookieValue, state = mangle(state)
	}
	query.Set("state", state)
	callback := do(t, s, call{method: http.MethodGet, path: ssoCallbackPath + "?" + query.Encode(),
		headers: map[string]string{"Cookie": ssoCookie + "=" + cookieValue}})
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback: %d %s", callback.Code, callback.Body.String())
	}
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.Value != "" {
			return callback.Header().Get("Location"), cookie
		}
	}
	return callback.Header().Get("Location"), nil
}

func TestSingleSignOn(t *testing.T) {
	s := newNetworkTestServer(t)
	idp := oidctest.New(t)
	s.sso.client = idp.Server.Client()
	admin := signIn(t, s)

	if offered := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session"})); offered.SSO != nil {
		t.Fatal("single sign-on offered before it is set up")
	}
	settings := map[string]any{"enabled": true, "issuer": idp.Server.URL, "client_id": idp.ClientID, "client_secret": idp.ClientSecret,
		"button_label": "Sign in with Test ID", "admin_groups": []string{"dg-admins"}, "allowed_groups": []string{"dg-users"}}
	if wrong := do(t, s, call{method: http.MethodPut, path: "/api/settings/sso", cookie: admin, body: map[string]any{"enabled": true, "issuer": "https://127.0.0.1:1", "client_id": "x", "client_secret": "y"}}); wrong.Code != http.StatusBadRequest {
		t.Fatalf("an unreachable issuer was saved: %d", wrong.Code)
	}
	saved := do(t, s, call{method: http.MethodPut, path: "/api/settings/sso", cookie: admin, body: settings})
	view := decode[ssoSettings](t, saved)
	if saved.Code != http.StatusOK || view.ClientSecret != "" || !view.SecretSet || view.RedirectURI != "https://deaconguard.example:8443"+ssoCallbackPath {
		t.Fatalf("save settings: %d %+v", saved.Code, view)
	}
	if offered := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session"})); offered.SSO == nil || offered.SSO.Label != "Sign in with Test ID" {
		t.Fatalf("sign-in page offer: %+v", offered.SSO)
	}

	// A first sign-in creates the account, with the default role.
	idp.Claims = map[string]any{"sub": "alice-1", "email": "Alice@Example.com", "email_verified": true, "groups": []string{"dg-users"}}
	next, cookie := ssoSignIn(t, s, idp, nil)
	if next != "/hosts" || cookie == nil {
		t.Fatalf("first sign-in: %s %v", next, cookie)
	}
	session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie}))
	if !session.Authenticated || session.Username != "alice@example.com" || session.Role != store.RoleViewer || !session.SSOAccount {
		t.Fatalf("session: %+v", session)
	}
	if refused := do(t, s, call{method: http.MethodPost, path: "/api/account/password", cookie: cookie, body: map[string]string{"current_password": "x", "new_password": "y"}}); refused.Code != http.StatusConflict {
		t.Fatalf("an SSO account changing its password: %d", refused.Code)
	}

	// Groups decide the role at every sign-in.
	idp.Claims["groups"] = []string{"dg-users", "dg-admins"}
	if _, cookie = ssoSignIn(t, s, idp, nil); decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie})).Role != store.RoleAdmin {
		t.Fatal("the admin group didn't make alice an admin")
	}
	idp.Claims["groups"] = []string{"dg-users"}
	if _, cookie = ssoSignIn(t, s, idp, nil); decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie})).Role != store.RoleViewer {
		t.Fatal("leaving the admin group didn't make alice a viewer again")
	}

	// Required two-step sign-in is the provider's job for SSO accounts.
	if response := do(t, s, call{method: http.MethodPatch, path: "/api/settings/security", cookie: admin, body: map[string]bool{"require_mfa": false}}); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	alice, _ := store.UserByName("alice@example.com")
	if needs, _ := s.accountNeeds(alice); needs != "" {
		t.Fatalf("an SSO account needs: %s", needs)
	}
	if temporary := do(t, s, call{method: http.MethodPost, path: "/api/users/" + alice.ID + "/temporary-password", cookie: admin, body: map[string]string{"password": "temporary password 1"}}); temporary.Code != http.StatusConflict {
		t.Fatalf("a temporary password for an SSO account: %d", temporary.Code)
	}

	refusals := []struct {
		name, reason string
		claims       map[string]any
		mangle       func(string) (string, string)
		tamper       func(map[string]any)
	}{
		{name: "not in an allowed group", reason: "group", claims: map[string]any{"sub": "bob", "email": "bob@example.com", "groups": []string{"others"}}},
		{name: "an unverified email", reason: "account", claims: map[string]any{"sub": "carol", "email": "carol@example.com", "email_verified": false, "groups": "dg-users"}},
		{name: "a password account's name", reason: "exists", claims: map[string]any{"sub": "mallory", "email": "admin", "groups": []string{"dg-users"}}},
		{name: "another browser's state", reason: "expired", claims: map[string]any{"sub": "alice-1", "email": "alice@example.com", "groups": []string{"dg-users"}},
			mangle: func(state string) (string, string) { return "other", state }},
		{name: "another nonce", reason: "token", claims: map[string]any{"sub": "alice-1", "email": "alice@example.com", "groups": []string{"dg-users"}},
			tamper: func(claims map[string]any) { claims["nonce"] = "replayed" }},
		{name: "another audience", reason: "token", claims: map[string]any{"sub": "alice-1", "email": "alice@example.com", "groups": []string{"dg-users"}},
			tamper: func(claims map[string]any) { claims["aud"] = "another-app" }},
		{name: "an expired token", reason: "token", claims: map[string]any{"sub": "alice-1", "email": "alice@example.com", "groups": []string{"dg-users"}},
			tamper: func(claims map[string]any) { claims["exp"] = 1000 }},
	}
	for _, refusal := range refusals {
		idp.Claims, idp.Tamper = refusal.claims, refusal.tamper
		next, cookie := ssoSignIn(t, s, idp, refusal.mangle)
		if cookie != nil || next != "/login?sso_error="+refusal.reason {
			t.Errorf("%s: sent to %s, cookie %v", refusal.name, next, cookie != nil)
		}
	}
	idp.Tamper = nil

	// A disabled account can't sign in.
	if err := store.SetDisabled(alice.ID, true); err != nil {
		t.Fatal(err)
	}
	idp.Claims = map[string]any{"sub": "alice-1", "email": "alice@example.com", "groups": []string{"dg-users"}}
	if next, cookie := ssoSignIn(t, s, idp, nil); cookie != nil || !strings.HasSuffix(next, "sso_error=disabled") {
		t.Fatalf("a disabled account: %s", next)
	}

	// API tokens can't change single sign-on.
	token := decode[map[string]any](t, do(t, s, call{method: http.MethodPost, path: "/api/account/tokens", cookie: admin, body: map[string]string{"name": "ci", "role": "admin"}}))
	secret, _ := token["token"].(string)
	if secret == "" {
		t.Fatalf("token: %v", token)
	}
	if response := do(t, s, call{method: http.MethodGet, path: "/api/settings/sso", bearer: secret}); response.Code != http.StatusForbidden {
		t.Fatalf("an API token reading SSO settings: %d", response.Code)
	}
}
