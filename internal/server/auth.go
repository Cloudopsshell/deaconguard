package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"opsarmor/internal/local"
	"opsarmor/internal/store"
)

// sessionCookie uses the __Host- prefix, so browsers only accept it over
// HTTPS, for this exact host, on every path.
const sessionCookie = "__Host-opsarmor_session"

type userContextKey struct{}

// publicPaths answer without sign-in in network mode. The web app's files
// are public too; its data is not.
var publicPaths = map[string]bool{"/api/session": true, "/api/login": true, "/api/version": true}

// signedIn requires a valid session for the API in network mode.
func (s *Server) signedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		user, err := sessionUser(r)
		if errors.Is(err, store.ErrNoSession) {
			writeError(w, http.StatusUnauthorized, errors.New("sign in to OpsArmor"))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
	})
}

func sessionUser(r *http.Request) (store.User, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return store.User{}, store.ErrNoSession
	}
	return store.SessionUser(cookie.Value)
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
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeJSON(w, http.StatusOK, sessionResponse{Authenticated: true})
		return
	}
	user, err := sessionUser(r)
	if err != nil && !errors.Is(err, store.ErrNoSession) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true, Authenticated: err == nil, Username: user.Username})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeError(w, http.StatusConflict, errors.New("sign-in is only used when OpsArmor serves on the network"))
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
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token, expires, err := store.CreateSession(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	store.Audit(user.Username, "user.login", "", "", remote)
	writeJSON(w, http.StatusOK, sessionResponse{LoginRequired: true, Authenticated: true, Username: user.Username})
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
