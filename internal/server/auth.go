package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/local"
	"deaconguard/internal/store"
)

// sessionCookie uses the __Host- prefix, so browsers only accept it over
// HTTPS, for this exact host, on every path.
const sessionCookie = "__Host-deaconguard_session"

type userContextKey struct{}

type sessionContextKey struct{}

// publicPaths answer without sign-in in network mode. The web app's files
// are public too; its data is not.
var publicPaths = map[string]bool{
	"/api/session": true, "/api/login": true, "/api/version": true,
	"/api/login/passkey/options": true, "/api/login/passkey": true,
}

// pendingPaths are all a session waiting for its second sign-in step may use.
var pendingPaths = map[string]bool{"/api/login/mfa": true, "/api/logout": true}

// restrictedPaths are all an account may use while it must change its
// password or set up two-step sign-in, which /api/session reports.
var restrictedPaths = map[string]bool{
	"/api/logout": true, "/api/account": true, "/api/account/password": true,
	"/api/account/mfa": true, "/api/account/mfa/confirm": true,
	"/api/account/passkeys": true, "/api/account/passkeys/options": true,
}

// signedIn requires a valid session for the API in network mode. A session
// still waiting for its second step, or an account that must first change
// its password or set up two-step sign-in, reaches only the paths for that.
func (s *Server) signedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if bearer, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found {
			s.tokenSignedIn(next, w, r, strings.TrimSpace(bearer))
			return
		}
		user, session, err := sessionUser(r)
		if errors.Is(err, store.ErrNoSession) {
			writeError(w, http.StatusUnauthorized, errors.New("sign in to DeaconGuard"))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if session.Stage != store.StageFull {
			if !pendingPaths[r.URL.Path] {
				writeError(w, http.StatusUnauthorized, errors.New("enter the code from your authenticator app to finish signing in"))
				return
			}
		} else if needs, err := s.accountNeeds(user); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		} else if needs != "" && !restrictedPaths[r.URL.Path] {
			writeError(w, http.StatusForbidden, errors.New(needs))
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey{}, user)
		ctx = context.WithValue(ctx, sessionContextKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tokenRefused reports the paths API tokens never reach: accounts, tokens
// and sign-in security, so a leaked token can't make itself a lasting way in.
func tokenRefused(path string) bool {
	for _, prefix := range []string{"/api/account", "/api/users", "/api/tokens", "/api/settings/security", "/api/login", "/api/logout", "/api/session"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// tokenSignedIn serves an API request made with an API token, as its
// account, with the token's role.
func (s *Server) tokenSignedIn(next http.Handler, w http.ResponseWriter, r *http.Request, bearer string) {
	remote := remoteIP(r)
	if s.limiter.blocked("token", remote) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many requests with a wrong API token; wait 15 minutes"))
		return
	}
	user, token, err := store.AuthenticateAPIToken(bearer, remote)
	if errors.Is(err, store.ErrBadAPIToken) {
		s.limiter.fail("token", remote)
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if tokenRefused(r.URL.Path) {
		writeError(w, http.StatusForbidden, errors.New("API tokens can't manage accounts, tokens or sign-in; use the dashboard"))
		return
	}
	if needs, err := s.accountNeeds(user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	} else if needs != "" {
		writeError(w, http.StatusForbidden, errors.New("the token's account can't be used yet: "+needs))
		return
	}
	ctx := context.WithValue(r.Context(), userContextKey{}, user)
	ctx = context.WithValue(ctx, apiTokenContextKey{}, token)
	next.ServeHTTP(w, r.WithContext(ctx))
}

type apiTokenContextKey struct{}

// accountNeeds says what an account must do before it can use DeaconGuard,
// or "" when nothing.
func (s *Server) accountNeeds(user store.User) (string, error) {
	if user.MustChangePassword {
		return "choose a new password first: an administrator set a temporary one", nil
	}
	required, err := store.RequireMFA()
	if err != nil {
		return "", err
	}
	if required && !user.TwoStep() {
		return "set up two-step sign-in first, with an authenticator app or a passkey: it is required for every account", nil
	}
	return "", nil
}

func sessionUser(r *http.Request) (store.User, store.Session, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return store.User{}, store.Session{}, store.ErrNoSession
	}
	return store.SessionUser(cookie.Value)
}

// currentUser returns the signed-in account and session of a request.
func currentUser(r *http.Request) (store.User, store.Session, bool) {
	user, ok := r.Context().Value(userContextKey{}).(store.User)
	session, _ := r.Context().Value(sessionContextKey{}).(store.Session)
	return user, session, ok
}

// actor names who made a request, for the audit log.
func (s *Server) actor(r *http.Request) string {
	if user, ok := r.Context().Value(userContextKey{}).(store.User); ok {
		if token, ok := r.Context().Value(apiTokenContextKey{}).(store.APIToken); ok {
			return user.Username + " (API token " + token.Name + ")"
		}
		return user.Username
	}
	if !s.network {
		return local.Username() + " (local)"
	}
	return "anonymous"
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	store.Audit(s.actor(r), action, target, detail, remoteIP(r))
}

type sessionResponse struct {
	// LoginRequired is false in local mode, where there are no accounts.
	LoginRequired bool   `json:"login_required"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	// MFAPending: the password was right, and the second step is still
	// needed: a code from the authenticator app, or a passkey.
	MFAPending bool `json:"mfa_pending,omitempty"`
	// MFAMethods are the second steps the account can use: "app", "passkey".
	MFAMethods []string `json:"mfa_methods,omitempty"`
	// What the account must do before anything else, if anything.
	MustChangePassword bool `json:"must_change_password,omitempty"`
	MFASetupRequired   bool `json:"mfa_setup_required,omitempty"`
	// TwoStep: the account signs in with an authenticator app or a passkey.
	// It, MFAEnabled (the app) and RecoveryCodesLeft drive the reminders.
	TwoStep           bool `json:"two_step"`
	MFAEnabled        bool `json:"mfa_enabled"`
	Passkeys          int  `json:"passkeys"`
	RecoveryCodesLeft int  `json:"recovery_codes_left"`
	// Role decides what the dashboard offers; the server checks it on every request.
	Role string `json:"role,omitempty"`
	// Appearance is the account's saved mode and theme, if it chose one.
	Appearance json.RawMessage `json:"appearance,omitempty"`
}

// sessionFor describes a signed-in account to the dashboard.
func (s *Server) sessionFor(user store.User) (sessionResponse, error) {
	required, err := store.RequireMFA()
	if err != nil {
		return sessionResponse{}, err
	}
	return sessionResponse{
		LoginRequired: true, Authenticated: true, Username: user.Username,
		MustChangePassword: user.MustChangePassword, MFASetupRequired: required && !user.TwoStep(),
		TwoStep: user.TwoStep(), MFAEnabled: user.MFAEnabled, Passkeys: user.Passkeys, RecoveryCodesLeft: user.RecoveryCodesLeft,
		Role: user.Role, Appearance: appearanceJSON(user.Appearance),
	}, nil
}

// needs lets only accounts with at least role through. Local mode has no
// accounts, so everything is allowed there.
func (s *Server) needs(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.network {
			next(w, r)
			return
		}
		user, _, ok := currentUser(r)
		if !ok || !store.RoleAllows(user.Role, role) {
			writeError(w, http.StatusForbidden, fmt.Errorf("your role, %s, can't do this; it needs %s. Ask an administrator", roleName(user.Role), roleName(role)))
			return
		}
		next(w, r)
	}
}

// roleName is a role as the dashboard names it.
func roleName(role string) string {
	switch role {
	case store.RoleAdmin:
		return "Admin"
	case store.RoleOperator:
		return "Operator"
	case store.RoleViewer:
		return "Viewer"
	}
	return "none"
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeJSON(w, http.StatusOK, sessionResponse{Authenticated: true})
		return
	}
	user, session, err := sessionUser(r)
	if errors.Is(err, store.ErrNoSession) {
		writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if session.Stage != store.StageFull {
		writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true, Username: user.Username, MFAPending: true, MFAMethods: mfaMethods(user)})
		return
	}
	response, err := s.sessionFor(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// mfaMethods lists the second steps user can finish signing in with.
func mfaMethods(user store.User) []string {
	var methods []string
	if user.MFAEnabled {
		methods = append(methods, "app")
	}
	if user.Passkeys > 0 {
		methods = append(methods, "passkey")
	}
	return methods
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, session store.Session) {
	expires, _ := time.Parse(time.RFC3339, session.ExpiresAt)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// login checks the password. An account with two-step sign-in gets a
// session that can only finish signing in, at /api/login/mfa.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeError(w, http.StatusConflict, errors.New("sign-in is only used when DeaconGuard serves on the network"))
		return
	}
	remote := remoteIP(r)
	if s.limiter.blocked("login", remote) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many failed sign-in attempts; try again in a few minutes"))
		return
	}
	var request loginRequest
	if !readJSON(w, r, &request) {
		return
	}
	user, err := store.Authenticate(request.Username, []byte(request.Password))
	if errors.Is(err, store.ErrInvalidCredentials) {
		s.limiter.fail("login", remote)
		store.Audit(limitText(request.Username, 64), "user.login_failed", "", "", remote)
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if errors.Is(err, store.ErrAccountDisabled) {
		store.Audit(limitText(request.Username, 64), "user.login_failed", "", "account disabled", remote)
		writeError(w, http.StatusForbidden, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	stage := store.StageFull
	if user.TwoStep() {
		stage = store.StageMFA
	}
	token, session, err := store.CreateSession(user.ID, stage, remote, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, token, session)
	if stage == store.StageMFA {
		writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true, Username: user.Username, MFAPending: true, MFAMethods: mfaMethods(user)})
		return
	}
	store.MarkSignedIn(user.ID)
	store.Audit(user.Username, "user.login", "", "", remote)
	response, err := s.sessionFor(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type mfaLoginRequest struct {
	// Code is from the authenticator app, or one of the recovery codes.
	Code string `json:"code"`
}

// loginMFA finishes signing in with a code from the authenticator app or a
// recovery code, replacing the waiting session with a full one.
func (s *Server) loginMFA(w http.ResponseWriter, r *http.Request) {
	remote := remoteIP(r)
	if s.limiter.blocked("mfa", remote) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many wrong codes; try again in a few minutes"))
		return
	}
	user, session, ok := currentUser(r)
	if !ok || session.Stage != store.StageMFA {
		writeError(w, http.StatusConflict, errors.New("sign in with your password first"))
		return
	}
	var request mfaLoginRequest
	if !readJSON(w, r, &request) {
		return
	}
	code := strings.TrimSpace(request.Code)
	method := "authenticator app"
	err := store.CheckTOTP(user.ID, code, time.Now())
	if errors.Is(err, store.ErrWrongCode) && len(code) > 7 {
		method = "recovery code"
		err = store.UseRecoveryCode(user.ID, code)
	}
	if errors.Is(err, store.ErrWrongCode) {
		s.limiter.fail("mfa", remote)
		store.Audit(user.Username, "user.login_failed", "", "wrong two-step code", remote)
		writeError(w, http.StatusUnauthorized, errors.New("that code is not right; use the current code from your authenticator app, or a recovery code"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = store.DeleteSession(cookie.Value)
	}
	token, full, err := store.CreateSession(user.ID, store.StageFull, remote, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, token, full)
	store.MarkSignedIn(user.ID)
	store.Audit(user.Username, "user.login", "", "with "+method, remote)
	user, err = store.GetUser(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	response, err := s.sessionFor(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.audit(r, "user.logout", "", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := store.AuditLog(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

const (
	// maxFailures failed attempts from one address within failureWindow
	// block that address until the window passes.
	maxFailures   = 10
	failureWindow = 15 * time.Minute
)

// failureLimiter slows password and token guessing per client address.
type failureLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newFailureLimiter() *failureLimiter {
	return &failureLimiter{failures: make(map[string][]time.Time)}
}

func (l *failureLimiter) recent(key string) []time.Time {
	cutoff := time.Now().Add(-failureWindow)
	kept := l.failures[key][:0]
	for _, at := range l.failures[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}

func (l *failureLimiter) blocked(kind, remote string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(kind+" "+remote)) >= maxFailures
}

func (l *failureLimiter) fail(kind, remote string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := kind + " " + remote
	l.failures[key] = append(l.recent(key), time.Now())
	if len(l.failures) > 10_000 {
		// Bound memory under a flood from many addresses.
		for other := range l.failures {
			l.recent(other)
		}
	}
}
