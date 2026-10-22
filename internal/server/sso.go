package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/oidc"
	"deaconguard/internal/store"
)

const (
	// ssoCookie ties a sign-in started in this browser to its callback. It
	// is Lax, unlike the session cookie, because the provider sends the
	// browser back from another site.
	ssoCookie = "__Host-deaconguard_sso"
	// ssoLifetime is how long a sign-in at the provider may take.
	ssoLifetime = 10 * time.Minute
	// maxSSOPending bounds the sign-ins waiting for the provider.
	maxSSOPending = 10_000
	// providerLifetime is how long a discovery document is kept.
	providerLifetime = time.Hour
	ssoCallbackPath  = "/api/login/sso/callback"
)

type ssoPending struct {
	nonce, verifier, next string
	expires               time.Time
}

// ssoState keeps the provider's discovery and the sign-ins in progress.
type ssoState struct {
	mu       sync.Mutex
	client   *http.Client
	provider *oidc.Provider
	issuer   string
	fetched  time.Time
	pending  map[string]ssoPending
}

func (st *ssoState) providerFor(ctx context.Context, issuer string) (*oidc.Provider, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.provider != nil && st.issuer == issuer && time.Since(st.fetched) < providerLifetime {
		return st.provider, nil
	}
	if st.client == nil {
		st.client = oidc.NewClient(nil)
	}
	provider, err := oidc.Discover(ctx, st.client, issuer)
	if err != nil {
		return nil, err
	}
	st.provider, st.issuer, st.fetched = provider, issuer, time.Now()
	return provider, nil
}

// forget drops the cached discovery, after the settings change.
func (st *ssoState) forget() {
	st.mu.Lock()
	st.provider = nil
	st.mu.Unlock()
}

func (st *ssoState) add(state string, entry ssoPending) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	if st.pending == nil {
		st.pending = map[string]ssoPending{}
	}
	for key, value := range st.pending {
		if now.After(value.expires) {
			delete(st.pending, key)
		}
	}
	if len(st.pending) >= maxSSOPending {
		return errors.New("too many sign-ins at once")
	}
	entry.expires = now.Add(ssoLifetime)
	st.pending[state] = entry
	return nil
}

func (st *ssoState) take(state string) (ssoPending, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	entry, ok := st.pending[state]
	delete(st.pending, state)
	return entry, ok && time.Now().Before(entry.expires)
}

// redirectURI is where the provider sends the browser back: the address the
// browser used for the dashboard. Register exactly this with the provider.
func redirectURI(r *http.Request) string {
	return "https://" + r.Host + ssoCallbackPath
}

// ssoFailed sends the browser back to the sign-in page with one of a fixed
// set of reasons, which the page explains; the details go to the audit log
// and the server's log, never into the address.
func (s *Server) ssoFailed(w http.ResponseWriter, r *http.Request, reason, username, detail string) {
	store.Audit(limitText(username, 64), "user.login_failed", "", "single sign-on: "+limitText(detail, 400), remoteIP(r))
	log.Printf("Single sign-on failed: %s", detail)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(reason), http.StatusSeeOther)
}

// startSSO sends the browser to the provider to sign in.
func (s *Server) startSSO(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	config, err := store.LoadSSOConfig()
	if err != nil || !config.Enabled {
		http.Redirect(w, r, "/login?sso_error=off", http.StatusSeeOther)
		return
	}
	provider, err := s.sso.providerFor(r.Context(), config.Issuer)
	if err != nil {
		s.ssoFailed(w, r, "provider", "", err.Error())
		return
	}
	state, err1 := oidc.Random(32)
	nonce, err2 := oidc.Random(32)
	verifier, err3 := oidc.Random(48)
	if err := errors.Join(err1, err2, err3); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.sso.add(state, ssoPending{nonce: nonce, verifier: verifier, next: safeNext(r.URL.Query().Get("next"))}); err != nil {
		s.ssoFailed(w, r, "busy", "", err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: state, Path: "/", MaxAge: int(ssoLifetime / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	scopes := append([]string{"openid", "email", "profile"}, config.Scopes...)
	http.Redirect(w, r, provider.AuthCodeURL(config.ClientID, redirectURI(r), state, nonce, verifier, scopes), http.StatusFound)
}

// safeNext keeps the page to open after signing in on this server.
func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.HasPrefix(next, "/\\") {
		return next
	}
	return "/"
}

// ssoCallback finishes a sign-in: checks the state and the ID token, finds
// or creates the account, and starts a session.
func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	query := r.URL.Query()
	if s.limiter.blocked("login", remoteIP(r)) {
		http.Redirect(w, r, "/login?sso_error=limited", http.StatusSeeOther)
		return
	}
	cookie, err := r.Cookie(ssoCookie)
	state := query.Get("state")
	if err != nil || state == "" || cookie.Value != state {
		s.limiter.fail("login", remoteIP(r))
		s.ssoFailed(w, r, "expired", "", "the callback's state doesn't match this browser's sign-in")
		return
	}
	pending, ok := s.sso.take(state)
	if !ok {
		s.ssoFailed(w, r, "expired", "", "the sign-in took longer than 10 minutes, or was already finished")
		return
	}
	if reason := query.Get("error"); reason != "" {
		s.ssoFailed(w, r, "denied", "", "the provider answered: "+reason+" "+query.Get("error_description"))
		return
	}
	config, err := store.LoadSSOConfig()
	if err != nil || !config.Enabled {
		s.ssoFailed(w, r, "off", "", "single sign-on was turned off during the sign-in")
		return
	}
	provider, err := s.sso.providerFor(r.Context(), config.Issuer)
	if err != nil {
		s.ssoFailed(w, r, "provider", "", err.Error())
		return
	}
	token, err := provider.Exchange(r.Context(), config.ClientID, config.ClientSecret, redirectURI(r), query.Get("code"), pending.verifier)
	if err != nil {
		s.ssoFailed(w, r, "provider", "", err.Error())
		return
	}
	claims, err := provider.Verify(r.Context(), token, config.ClientID, pending.nonce, time.Now())
	if err != nil {
		s.limiter.fail("login", remoteIP(r))
		s.ssoFailed(w, r, "token", "", err.Error())
		return
	}
	user, reason, detail := s.ssoAccount(config, claims)
	if reason != "" {
		s.ssoFailed(w, r, reason, user.Username, detail)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if old, err := r.Cookie(sessionCookie); err == nil {
		_ = store.DeleteSession(old.Value)
	}
	session, full, err := store.CreateSession(user.ID, store.StageFull, remoteIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, session, full)
	store.MarkSignedIn(user.ID)
	store.Audit(user.Username, "user.login", "", "with single sign-on", remoteIP(r))
	http.Redirect(w, r, pending.next, http.StatusSeeOther)
}

// ssoRole is the role groups give, and whether groups decide it.
func ssoRole(config store.SSOConfig, groups []string) (string, bool) {
	member := func(list []string) bool {
		for _, group := range list {
			if slices.Contains(groups, group) {
				return true
			}
		}
		return false
	}
	mapped := len(config.AdminGroups) > 0 || len(config.OperatorGroups) > 0
	switch {
	case member(config.AdminGroups):
		return store.RoleAdmin, mapped
	case member(config.OperatorGroups):
		return store.RoleOperator, mapped
	}
	return config.DefaultRole, mapped
}

// googleIssuer is Google's OpenID Connect issuer.
const googleIssuer = "https://accounts.google.com"

// domainRefusal says why claims aren't in an allowed email domain, or ""
// when they are or no domains are set. Google's ID tokens also carry hd, the
// Google Workspace domain that manages the account: Google says to check it,
// because a personal Google account can have a verified address at a
// company's domain that the company's Workspace doesn't manage.
func domainRefusal(config store.SSOConfig, claims oidc.Claims) string {
	if len(config.AllowedDomains) == 0 {
		return ""
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	at := strings.LastIndex(email, "@")
	if at < 0 || !claims.EmailIsVerified() || !slices.Contains(config.AllowedDomains, email[at+1:]) {
		return fmt.Sprintf("%q isn't a verified email in an allowed domain", email)
	}
	if claims.Issuer == googleIssuer {
		if hd := strings.ToLower(claims.String("hd")); !slices.Contains(config.AllowedDomains, hd) {
			return fmt.Sprintf("%s isn't managed by an allowed Google Workspace domain (hd %q); a personal Google account can't use a company address here", email, hd)
		}
	}
	return ""
}

// ssoAccount finds the account for claims, or creates it, and checks it may
// sign in. reason is one of the sign-in page's reasons when it may not.
func (s *Server) ssoAccount(config store.SSOConfig, claims oidc.Claims) (store.User, string, string) {
	groups := claims.Strings(config.GroupsClaim)
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if detail := domainRefusal(config, claims); detail != "" {
		return store.User{Username: email}, "domain", detail
	}
	if len(config.AllowedGroups) > 0 {
		allowed := append(append(append([]string{}, config.AllowedGroups...), config.AdminGroups...), config.OperatorGroups...)
		if !slices.ContainsFunc(groups, func(group string) bool { return slices.Contains(allowed, group) }) {
			return store.User{Username: email}, "group", fmt.Sprintf("%s isn't in an allowed group (the provider sent %d groups in %q)",
				claims.Subject, len(groups), config.GroupsClaim)
		}
	}
	role, mapped := ssoRole(config, groups)
	subject := claims.Issuer + "|" + claims.Subject
	user, err := store.UserBySSOSubject(subject)
	if errors.Is(err, store.ErrUnknownUser) {
		username := claims.PreferredUsername
		if config.UsernameClaim != "preferred_username" {
			if !claims.EmailIsVerified() {
				return store.User{Username: email}, "account", "the provider hasn't verified the email " + email
			}
			username = email
		}
		if username == "" {
			return store.User{}, "account", fmt.Sprintf("the ID token has no %s claim to name the account", config.UsernameClaim)
		}
		user, err = store.AddSSOUser(username, role, subject)
		if errors.Is(err, store.ErrSSOUsernameTaken) {
			return store.User{Username: username}, "exists", username + ": " + err.Error()
		}
		if err != nil {
			return store.User{Username: username}, "account", err.Error()
		}
		store.Audit("single sign-on", "user.add", user.Username, "role "+role+", from "+claims.Issuer, "")
		return user, "", ""
	}
	if err != nil {
		return store.User{}, "account", err.Error()
	}
	if user.Disabled {
		return user, "disabled", "the account is disabled"
	}
	if mapped && user.Role != role {
		if err := store.SetRole(user.ID, role); err != nil {
			log.Printf("Single sign-on kept %s's role %s, not %s from its groups: %v", user.Username, user.Role, role, err)
		} else {
			store.Audit("single sign-on", "user.role", user.Username, roleName(user.Role)+" to "+roleName(role)+", from the provider's groups", "")
			user.Role = role
		}
	}
	return user, "", ""
}

// scopePattern is what an OAuth scope may look like here (RFC 6749 3.3,
// without quotes or backslashes).
var scopePattern = regexp.MustCompile(`^[!#-\[\]-~]{1,100}$`)

// ssoSettings is the single sign-on settings as the dashboard sees them.
type ssoSettings struct {
	store.SSOConfig
	// SecretSet: a client secret is saved; it is never sent back.
	SecretSet bool `json:"secret_set"`
	// RedirectURI is the address to register with the provider.
	RedirectURI string `json:"redirect_uri"`
}

func (s *Server) getSSOSettings(w http.ResponseWriter, r *http.Request) {
	config, err := store.LoadSSOConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	set := config.ClientSecret != ""
	config.ClientSecret = ""
	writeJSON(w, http.StatusOK, ssoSettings{SSOConfig: config, SecretSet: set, RedirectURI: redirectURI(r)})
}

func cleanList(list []string, lower bool) []string {
	var out []string
	for _, item := range list {
		item = strings.TrimSpace(item)
		if lower {
			item = strings.ToLower(item)
		}
		if item != "" && len(item) <= 256 && len(out) < 100 && !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return out
}

// saveSSOSettings saves the settings. Turning single sign-on on checks the
// provider's discovery document first.
func (s *Server) saveSSOSettings(w http.ResponseWriter, r *http.Request) {
	var request store.SSOConfig
	if !readJSON(w, r, &request) {
		return
	}
	saved, err := store.LoadSSOConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	config := store.SSOConfig{
		Enabled: request.Enabled, Issuer: strings.TrimSpace(request.Issuer), ClientID: strings.TrimSpace(request.ClientID),
		ClientSecret: request.ClientSecret, ButtonLabel: limitText(strings.TrimSpace(request.ButtonLabel), 60),
		UsernameClaim: request.UsernameClaim, GroupsClaim: strings.TrimSpace(request.GroupsClaim),
		AllowedDomains: cleanList(request.AllowedDomains, true), AllowedGroups: cleanList(request.AllowedGroups, false),
		AdminGroups: cleanList(request.AdminGroups, false), OperatorGroups: cleanList(request.OperatorGroups, false),
		DefaultRole: request.DefaultRole,
	}
	for _, scope := range cleanList(request.Scopes, false) {
		if !scopePattern.MatchString(scope) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("%q isn't a scope; scopes are words such as groups", scope))
			return
		}
		if !slices.Contains([]string{"openid", "email", "profile"}, scope) {
			config.Scopes = append(config.Scopes, scope)
		}
	}
	if config.ClientSecret == "" {
		config.ClientSecret = saved.ClientSecret
	}
	if config.UsernameClaim != "preferred_username" {
		config.UsernameClaim = "email"
	}
	if config.GroupsClaim == "" {
		config.GroupsClaim = "groups"
	}
	if config.DefaultRole != store.RoleOperator && config.DefaultRole != store.RoleAdmin {
		config.DefaultRole = store.RoleViewer
	}
	if config.Enabled {
		switch {
		case config.Issuer == "" || config.ClientID == "":
			writeError(w, http.StatusBadRequest, errors.New("give the provider's issuer URL and the client ID"))
			return
		case config.ClientSecret == "":
			writeError(w, http.StatusBadRequest, errors.New("give the client secret; DeaconGuard signs in as a confidential client"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		client := s.sso.client
		if client == nil {
			client = oidc.NewClient(nil)
		}
		if _, err := oidc.Discover(ctx, client, config.Issuer); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := store.SaveSSOConfig(config); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.sso.forget()
	state := "off"
	if config.Enabled {
		state = "on, " + config.Issuer
	}
	s.audit(r, "settings.sso", "", state)
	s.getSSOSettings(w, r)
}

// errSSOAccount refuses password and two-step changes to accounts that sign
// in with single sign-on.
var errSSOAccount = errors.New("this account signs in with single sign-on: its password and two-step sign-in are managed by your identity provider")

// passwordAccount lets only accounts with a password through.
func passwordAccount(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if user, _, ok := currentUser(r); ok && user.SSO {
			writeError(w, http.StatusConflict, errSSOAccount)
			return
		}
		next(w, r)
	}
}

// ssoButton tells the sign-in page to offer single sign-on.
type ssoButton struct {
	Label string `json:"label"`
}

func ssoOffer() *ssoButton {
	config, err := store.LoadSSOConfig()
	if err != nil || !config.Enabled {
		return nil
	}
	label := config.ButtonLabel
	if label == "" {
		label = "Sign in with single sign-on"
	}
	return &ssoButton{Label: label}
}
