package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/store"
	"deaconguard/internal/totp"
)

// login signs username in and returns the session cookie and the response.
func login(t *testing.T, s *Server, username, password string) (*http.Cookie, sessionResponse, int) {
	t.Helper()
	response := do(t, s, call{method: http.MethodPost, path: "/api/login", body: map[string]string{"username": username, "password": password}})
	var cookie *http.Cookie
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == sessionCookie {
			cookie = candidate
		}
	}
	var body sessionResponse
	if response.Code == http.StatusOK {
		body = decode[sessionResponse](t, response)
	}
	return cookie, body, response.Code
}

// currentCode is what the authenticator app shows now.
func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.Code(secret, totp.Step(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// setUpMFA turns on two-step sign-in for the account of cookie and returns
// its secret and recovery codes.
func setUpMFA(t *testing.T, s *Server, cookie *http.Cookie, password string) (string, []string) {
	t.Helper()
	started := do(t, s, call{method: http.MethodPost, path: "/api/account/mfa", body: map[string]string{"password": password}, cookie: cookie})
	setup := decode[mfaStartResponse](t, started)
	if started.Code != http.StatusOK || setup.Secret == "" || !strings.HasPrefix(setup.URI, "otpauth://totp/DeaconGuard:") {
		t.Fatalf("start MFA: %d %+v", started.Code, setup)
	}
	if wrong := do(t, s, call{method: http.MethodPost, path: "/api/account/mfa/confirm", body: map[string]string{"code": "000000"}, cookie: cookie}); wrong.Code != http.StatusBadRequest {
		t.Fatalf("a wrong confirmation code: %d", wrong.Code)
	}
	confirmed := do(t, s, call{method: http.MethodPost, path: "/api/account/mfa/confirm", body: map[string]string{"code": currentCode(t, setup.Secret)}, cookie: cookie})
	codes := decode[recoveryCodesResponse](t, confirmed).RecoveryCodes
	if confirmed.Code != http.StatusOK || len(codes) != store.RecoveryCodeCount {
		t.Fatalf("confirm MFA: %d %v", confirmed.Code, codes)
	}
	return setup.Secret, codes
}

func TestTwoStepSignIn(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	secret, codes := setUpMFA(t, s, cookie, testPassword)
	if session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: cookie})); !session.MFAEnabled || session.RecoveryCodesLeft != 10 {
		t.Fatalf("session after setup = %+v", session)
	}

	// The password alone gives a session that can only finish signing in.
	pending, body, code := login(t, s, "admin", testPassword)
	if code != http.StatusOK || !body.MFAPending || body.Authenticated {
		t.Fatalf("password step: %d %+v", code, body)
	}
	if blocked := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: pending}); blocked.Code != http.StatusUnauthorized {
		t.Fatalf("hosts before the second step: %d", blocked.Code)
	}
	if wrong := do(t, s, call{method: http.MethodPost, path: "/api/login/mfa", body: map[string]string{"code": "123456"}, cookie: pending}); wrong.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong code: %d", wrong.Code)
	}
	// The code of this 30 seconds was used to confirm the setup: it works once.
	if replay := do(t, s, call{method: http.MethodPost, path: "/api/login/mfa", body: map[string]string{"code": currentCode(t, secret)}, cookie: pending}); replay.Code != http.StatusUnauthorized {
		t.Fatalf("a used code was accepted again: %d", replay.Code)
	}

	// A recovery code finishes signing in, once.
	finished := do(t, s, call{method: http.MethodPost, path: "/api/login/mfa", body: map[string]string{"code": strings.ToUpper(codes[0])}, cookie: pending})
	if finished.Code != http.StatusOK || !decode[sessionResponse](t, finished).Authenticated || decode[sessionResponse](t, finished).RecoveryCodesLeft != 9 {
		t.Fatalf("recovery code: %d %s", finished.Code, finished.Body.String())
	}
	full := finished.Result().Cookies()[0]
	if full.Value == pending.Value {
		t.Fatal("the session token was not replaced after the second step")
	}
	if hosts := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: full}); hosts.Code != http.StatusOK {
		t.Fatalf("hosts after signing in: %d", hosts.Code)
	}
	if stale := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: pending}); stale.Code != http.StatusUnauthorized {
		t.Fatalf("the waiting session still works: %d", stale.Code)
	}
	again, _, _ := login(t, s, "admin", testPassword)
	if reused := do(t, s, call{method: http.MethodPost, path: "/api/login/mfa", body: map[string]string{"code": codes[0]}, cookie: again}); reused.Code != http.StatusUnauthorized {
		t.Fatalf("a used recovery code was accepted again: %d", reused.Code)
	}
}

func TestAccountsAdminActions(t *testing.T) {
	s := newNetworkTestServer(t)
	admin := signIn(t, s)
	const temporary = "Temporary-pass-123"

	created := do(t, s, call{method: http.MethodPost, path: "/api/users", body: map[string]string{"username": "bob", "password": temporary}, cookie: admin})
	bob := decode[store.User](t, created)
	if created.Code != http.StatusCreated || !bob.MustChangePassword {
		t.Fatalf("create bob: %d %+v", created.Code, bob)
	}

	// A temporary password must be changed before anything else.
	bobCookie, body, _ := login(t, s, "bob", temporary)
	if !body.MustChangePassword {
		t.Fatalf("bob's first sign-in = %+v", body)
	}
	if blocked := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: bobCookie}); blocked.Code != http.StatusForbidden {
		t.Fatalf("hosts with a temporary password: %d", blocked.Code)
	}
	if same := do(t, s, call{method: http.MethodPost, path: "/api/account/password", body: passwordChangeRequest{CurrentPassword: temporary, NewPassword: temporary}, cookie: bobCookie}); same.Code != http.StatusBadRequest {
		t.Fatalf("reusing the temporary password: %d", same.Code)
	}
	if changed := do(t, s, call{method: http.MethodPost, path: "/api/account/password", body: passwordChangeRequest{CurrentPassword: temporary, NewPassword: "Bobs-own-password-1"}, cookie: bobCookie}); changed.Code != http.StatusOK {
		t.Fatalf("change password: %d %s", changed.Code, changed.Body.String())
	}
	if hosts := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: bobCookie}); hosts.Code != http.StatusOK {
		t.Fatalf("hosts after changing the password: %d", hosts.Code)
	}

	// Requiring two-step sign-in sends accounts without it to set it up. The
	// admin who turns it on must use it first.
	if early := do(t, s, call{method: http.MethodPatch, path: "/api/settings/security", body: securitySettings{RequireMFA: true}, cookie: admin}); early.Code != http.StatusConflict {
		t.Fatalf("requiring MFA without using it: %d", early.Code)
	}
	setUpMFA(t, s, admin, testPassword)
	if set := do(t, s, call{method: http.MethodPatch, path: "/api/settings/security", body: securitySettings{RequireMFA: true}, cookie: admin}); set.Code != http.StatusOK {
		t.Fatalf("require MFA: %d", set.Code)
	}
	if session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session", cookie: bobCookie})); !session.MFASetupRequired {
		t.Fatalf("bob's session with MFA required = %+v", session)
	}
	if blocked := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: bobCookie}); blocked.Code != http.StatusForbidden {
		t.Fatalf("hosts without MFA while it is required: %d", blocked.Code)
	}
	setUpMFA(t, s, bobCookie, "Bobs-own-password-1")
	if hosts := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: bobCookie}); hosts.Code != http.StatusOK {
		t.Fatalf("hosts after setting up MFA: %d", hosts.Code)
	}
	if removeOwn := do(t, s, call{method: http.MethodPost, path: "/api/account/mfa/remove", body: map[string]string{"password": "Bobs-own-password-1"}, cookie: bobCookie}); removeOwn.Code != http.StatusConflict {
		t.Fatalf("removing MFA while it is required: %d", removeOwn.Code)
	}

	// A lost phone: an admin resets bob's MFA, which signs him out everywhere.
	if self := do(t, s, call{method: http.MethodPost, path: "/api/users/" + adminID(t) + "/reset-mfa", cookie: admin}); self.Code != http.StatusConflict {
		t.Fatalf("resetting your own MFA from Accounts: %d", self.Code)
	}
	if reset := do(t, s, call{method: http.MethodPost, path: "/api/users/" + bob.ID + "/reset-mfa", cookie: admin}); reset.Code != http.StatusOK {
		t.Fatalf("reset bob's MFA: %d", reset.Code)
	}
	if signedOut := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: bobCookie}); signedOut.Code != http.StatusUnauthorized {
		t.Fatalf("bob still signed in after the reset: %d", signedOut.Code)
	}
	if user, _ := store.GetUser(bob.ID); user.MFAEnabled || user.RecoveryCodesLeft != 0 {
		t.Fatalf("bob after the reset = %+v", user)
	}

	// A forgotten password: a temporary one, to change at the next sign-in.
	if temp := do(t, s, call{method: http.MethodPost, path: "/api/users/" + bob.ID + "/temporary-password", body: map[string]string{"password": temporary}, cookie: admin}); temp.Code != http.StatusOK {
		t.Fatalf("temporary password: %d", temp.Code)
	}
	if _, body, _ := login(t, s, "bob", temporary); !body.MustChangePassword {
		t.Fatalf("bob after a temporary password = %+v", body)
	}

	// Disabling signs out and refuses sign-in; the last account stays.
	if disable := do(t, s, call{method: http.MethodPatch, path: "/api/users/" + bob.ID, body: map[string]bool{"disabled": true}, cookie: admin}); disable.Code != http.StatusOK {
		t.Fatalf("disable bob: %d", disable.Code)
	}
	if _, _, code := login(t, s, "bob", temporary); code != http.StatusForbidden {
		t.Fatalf("a disabled account signed in: %d", code)
	}
	if err := store.SetDisabled(adminID(t), true); err != store.ErrLastAccount {
		t.Fatalf("disabling the last enabled account: %v", err)
	}
	if removed := do(t, s, call{method: http.MethodDelete, path: "/api/users/" + bob.ID, cookie: admin}); removed.Code != http.StatusNoContent {
		t.Fatalf("remove bob: %d", removed.Code)
	}

	audit, _ := store.AuditLog(200)
	actions := map[string]bool{}
	for _, entry := range audit {
		actions[entry.Action] = true
	}
	for _, want := range []string{"user.add", "user.passwd", "settings.require_mfa", "user.mfa_enable", "user.mfa_reset", "user.disable", "user.remove"} {
		if !actions[want] {
			t.Errorf("audit log lacks %s", want)
		}
	}
}

func adminID(t *testing.T) string {
	t.Helper()
	user, err := store.UserByName("admin")
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func TestSessionsCanBeListedAndEnded(t *testing.T) {
	s := newNetworkTestServer(t)
	first := signIn(t, s)
	second := signIn(t, s)
	account := decode[accountResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/account", cookie: first}))
	if len(account.Sessions) != 2 {
		t.Fatalf("sessions = %+v", account.Sessions)
	}
	var current, other store.Session
	for _, session := range account.Sessions {
		if session.Current {
			current = session
		} else {
			other = session
		}
	}
	if current.ID == "" || other.ID == "" {
		t.Fatalf("sessions = %+v", account.Sessions)
	}
	if self := do(t, s, call{method: http.MethodDelete, path: "/api/account/sessions/" + current.ID, cookie: first}); self.Code != http.StatusBadRequest {
		t.Fatalf("ending your own session from the list: %d", self.Code)
	}
	if ended := do(t, s, call{method: http.MethodDelete, path: "/api/account/sessions/others", cookie: first}); ended.Code != http.StatusOK {
		t.Fatalf("end other sessions: %d", ended.Code)
	}
	if gone := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: second}); gone.Code != http.StatusUnauthorized {
		t.Fatalf("the other session still works: %d", gone.Code)
	}
	if kept := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: first}); kept.Code != http.StatusOK {
		t.Fatalf("this session was signed out: %d", kept.Code)
	}
}

func TestLocalModeHasNoAccounts(t *testing.T) {
	s := newTestServer(t, nil)
	for _, path := range []string{"/api/users", "/api/account"} {
		if response := request(t, s, http.MethodGet, path, nil); response.Code != http.StatusConflict {
			t.Errorf("%s in local mode: %d", path, response.Code)
		}
	}
}
