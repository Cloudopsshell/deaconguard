package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

const (
	testOrigin   = "https://deaconguard.example:8443"
	testPassword = "correct horse battery"
	testPin      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func newNetworkTestServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	if _, err := NewNetwork(fstest.MapFS{}, nil, testPin); err == nil {
		t.Fatal("network mode started without any account")
	}
	if _, err := store.AddUser("admin", []byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	s, err := NewNetwork(fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}, nil, testPin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

type call struct {
	method, path string
	body         any
	cookie       *http.Cookie
	bearer       string
}

func do(t *testing.T, s *Server, c call) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if c.body != nil {
		encoded, err := json.Marshal(c.body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(c.method, testOrigin+c.path, reader)
	if c.method == http.MethodPost || c.method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, req)
	return recorder
}

func signIn(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	response := do(t, s, call{method: http.MethodPost, path: "/api/login", body: map[string]string{"username": "admin", "password": testPassword}})
	if response.Code != http.StatusOK {
		t.Fatalf("sign in: %d %s", response.Code, response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie {
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie is not locked down: %+v", cookie)
			}
			return cookie
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestNetworkModeRequiresSignIn(t *testing.T) {
	s := newNetworkTestServer(t)
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts"}); response.Code != http.StatusUnauthorized {
		t.Fatalf("hosts without sign-in: %d", response.Code)
	}
	session := decode[sessionResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/session"}))
	if !session.LoginRequired || session.Authenticated {
		t.Fatalf("session before sign-in: %+v", session)
	}
	wrong := do(t, s, call{method: http.MethodPost, path: "/api/login", body: map[string]string{"username": "admin", "password": "wrong password!"}})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", wrong.Code)
	}
	cookie := signIn(t, s)
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: cookie}); response.Code != http.StatusOK {
		t.Fatalf("hosts after sign-in: %d %s", response.Code, response.Body.String())
	}
	// Any host name is served in network mode, unlike local mode.
	if response := do(t, s, call{method: http.MethodGet, path: "/"}); response.Code != http.StatusOK {
		t.Fatalf("web app: %d", response.Code)
	}
	do(t, s, call{method: http.MethodPost, path: "/api/logout", body: map[string]any{}, cookie: cookie})
	if response := do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: cookie}); response.Code != http.StatusUnauthorized {
		t.Fatalf("hosts after sign-out: %d", response.Code)
	}
	entries, err := store.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]string, 0)
	for _, entry := range entries {
		actions = append(actions, entry.Action)
	}
	if got := strings.Join(actions, ","); got != "user.logout,user.login,user.login_failed" {
		t.Fatalf("audit log: %s", got)
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	s := newNetworkTestServer(t)
	for attempt := 0; attempt < maxFailures; attempt++ {
		do(t, s, call{method: http.MethodPost, path: "/api/login", body: map[string]string{"username": "admin", "password": "wrong"}})
	}
	response := do(t, s, call{method: http.MethodPost, path: "/api/login", body: map[string]string{"username": "admin", "password": testPassword}})
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: %d", maxFailures, response.Code)
	}
}

func TestAgentEnrollsAndRunsAScan(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)

	created := do(t, s, call{method: http.MethodPost, path: "/api/enrollment-tokens", body: map[string]string{"server_url": testOrigin}, cookie: cookie})
	if created.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", created.Code, created.Body.String())
	}
	tokenResponse := decode[enrollmentTokenResponse](t, created)
	token, err := agentapi.ParseToken(tokenResponse.Token)
	if err != nil {
		t.Fatal(err)
	}
	if token.ServerURL != testOrigin || token.Pin != testPin {
		t.Fatalf("token carries %+v", token)
	}

	enroll := agentapi.EnrollRequest{Secret: token.Secret, Hostname: "web-01", Username: "root", OS: "Ubuntu 24.04 LTS", Version: "test"}
	enrolled := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: enroll})
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", enrolled.Code, enrolled.Body.String())
	}
	identity := decode[agentapi.EnrollResponse](t, enrolled)
	if again := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: enroll}); again.Code != http.StatusUnauthorized {
		t.Fatalf("token reused: %d", again.Code)
	}
	bearer := identity.HostID + "." + identity.Credential
	if wrong := do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: identity.HostID + ".wrong"}); wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential: %d", wrong.Code)
	}

	started := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + identity.HostID + "/scans", body: map[string]any{"checks": []string{"config"}}, cookie: cookie})
	if started.Code != http.StatusAccepted {
		t.Fatalf("start scan: %d %s", started.Code, started.Body.String())
	}
	queued := decode[store.Scan](t, started)
	if queued.Status != store.ScanQueued {
		t.Fatalf("scan status %q, want queued", queued.Status)
	}
	if second := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + identity.HostID + "/scans", body: map[string]any{}, cookie: cookie}); second.Code != http.StatusConflict {
		t.Fatalf("second scan while queued: %d", second.Code)
	}

	jobResponse := do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer})
	if jobResponse.Code != http.StatusOK {
		t.Fatalf("job: %d %s", jobResponse.Code, jobResponse.Body.String())
	}
	job := decode[agentapi.Job](t, jobResponse)
	if job.ScanID != queued.ID || strings.Join(job.Checks, ",") != "config" || !job.AllowSudo {
		t.Fatalf("job %+v", job)
	}
	events := map[string]any{"events": []map[string]any{{"kind": "phase", "phase": "config", "message": "Security configuration"}, {"kind": "done", "message": "forged"}}}
	if response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/scans/" + job.ScanID + "/events", body: events, bearer: bearer}); response.Code != http.StatusNoContent {
		t.Fatalf("events: %d %s", response.Code, response.Body.String())
	}
	result := map[string]any{"report": map[string]any{
		"os": "Ubuntu 24.04 LTS", "checks_run": []string{"config"},
		// Package results from an agent are ignored; the server evaluates packages itself.
		"finding_count": 99,
		"check_results": map[string]any{"config": map[string]any{
			"status": "completed", "privileged": true, "summary": "1 finding",
			"findings": []map[string]any{{"rule": "ssh-root-login", "severity": "HIGH", "title": "Root can log in over SSH", "detail": "", "evidence": "PermitRootLogin yes"}},
		}},
	}}
	if response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/scans/" + job.ScanID + "/result", body: result, bearer: bearer}); response.Code != http.StatusAccepted {
		t.Fatalf("result: %d %s", response.Code, response.Body.String())
	}
	s.runner.wait()

	detail := decode[scanDetail](t, do(t, s, call{method: http.MethodGet, path: "/api/scans/" + job.ScanID, cookie: cookie}))
	if detail.Scan.Status != store.ScanSucceeded || detail.Scan.FindingCount != 0 {
		t.Fatalf("scan after result: %+v", detail.Scan)
	}
	if detail.Report["address"] != "web-01" || detail.Report["host_id"] != identity.HostID {
		t.Fatalf("report identity: %v %v", detail.Report["address"], detail.Report["host_id"])
	}
	logged := decode[eventsResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/scans/" + job.ScanID + "/events", cookie: cookie}))
	doneEvents := 0
	for _, event := range logged.Events {
		if event.Kind == "done" {
			doneEvents++
		}
	}
	if !logged.Finished || doneEvents != 1 {
		t.Fatalf("log finished=%t with %d done events", logged.Finished, doneEvents)
	}

	hosts := decode[[]store.HostSummary](t, do(t, s, call{method: http.MethodGet, path: "/api/hosts", cookie: cookie}))
	if len(hosts) != 1 || hosts[0].Agent == nil || hosts[0].Agent.OS != "Ubuntu 24.04 LTS" {
		t.Fatalf("hosts: %+v", hosts)
	}
	tokens := decode[[]store.EnrollmentToken](t, do(t, s, call{method: http.MethodGet, path: "/api/enrollment-tokens", cookie: cookie}))
	if len(tokens) != 1 || tokens[0].Status != "used" || tokens[0].HostID == nil || *tokens[0].HostID != identity.HostID {
		t.Fatalf("tokens: %+v", tokens)
	}

	// Removing the host revokes the agent.
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/hosts/" + identity.HostID, cookie: cookie}); response.Code != http.StatusOK {
		t.Fatalf("remove host: %d", response.Code)
	}
	if response := do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer}); response.Code != http.StatusUnauthorized {
		t.Fatalf("removed agent still accepted: %d", response.Code)
	}
}

func TestRevokedTokenCannotEnroll(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	tokenResponse := decode[enrollmentTokenResponse](t, do(t, s, call{method: http.MethodPost, path: "/api/enrollment-tokens", body: map[string]string{"server_url": testOrigin}, cookie: cookie}))
	if response := do(t, s, call{method: http.MethodDelete, path: "/api/enrollment-tokens/" + tokenResponse.ID, cookie: cookie}); response.Code != http.StatusOK {
		t.Fatalf("revoke: %d", response.Code)
	}
	token, _ := agentapi.ParseToken(tokenResponse.Token)
	response := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: agentapi.EnrollRequest{Secret: token.Secret, Hostname: "web-02"}})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token enrolled: %d", response.Code)
	}
}

func TestLocalModeRefusesAgentFeatures(t *testing.T) {
	s := newTestServer(t, nil)
	response := request(t, s, http.MethodPost, "/api/enrollment-tokens", map[string]string{"server_url": testOrigin})
	if response.Code != http.StatusConflict {
		t.Fatalf("token in local mode: %d", response.Code)
	}
	if response := request(t, s, http.MethodPost, "/agent/v1/enroll", map[string]string{}); response.Code == http.StatusCreated {
		t.Fatal("local mode accepted an enrollment")
	}
}
