package server

import (
	"context"
	"errors"
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
var publicPaths = map[string]bool{"/api/session": true, "/api/login": true, "/api/version": true}

// pendingPaths are all a session waiting for its second sign-in step may use.
var pendingPaths = map[string]bool{"/api/login/mfa": true, "/api/logout": true}

// restrictedPaths are all an account may use while it must change its
// password or set up two-step sign-in, which /api/session reports.
var restrictedPaths = map[string]bool{
	"/api/logout": true, "/api/account": true, "/api/account/password": true,
	"/api/account/mfa": true, "/api/account/mfa/confirm": true,
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
	if required && !user.MFAEnabled {
		return "set up two-step sign-in first: it is required for every account", nil
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
	// MFAPending: the password was right, and the code from the
	// authenticator app is still needed.
	MFAPending bool `json:"mfa_pending,omitempty"`
	// What the account must do before anything else, if anything.
	MustChangePassword bool `json:"must_change_password,omitempty"`
	MFASetupRequired   bool `json:"mfa_setup_required,omitempty"`
	// MFAEnabled and RecoveryCodesLeft drive the dashboard's reminders.
	MFAEnabled        bool `json:"mfa_enabled"`
	RecoveryCodesLeft int  `json:"recovery_codes_left"`
}

// sessionFor describes a signed-in account to the dashboard.
func (s *Server) sessionFor(user store.User) (sessionResponse, error) {
	required, err := store.RequireMFA()
	if err != nil {
		return sessionResponse{}, err
	}
	return sessionResponse{
		LoginRequired: true, Authenticated: true, Username: user.Username,
		MustChangePassword: user.MustChangePassword, MFASetupRequired: required && !user.MFAEnabled,
		MFAEnabled: user.MFAEnabled, RecoveryCodesLeft: user.RecoveryCodesLeft,
	}, nil
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
		writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true, Username: user.Username, MFAPending: true})
		return
	}
	response, err := s.sessionFor(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
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
	if user.MFAEnabled {
		stage = store.StageMFA
	}
	token, session, err := store.CreateSession(user.ID, stage, remote, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, token, session)
	if stage == store.StageMFA {
		writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true, Username: user.Username, MFAPending: true})
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
