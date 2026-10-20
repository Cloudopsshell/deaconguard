package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/store"
	"deaconguard/internal/webauthn"
)

// passkeyChallengeLifetime is how long a registration or sign-in may take.
const passkeyChallengeLifetime = 5 * time.Minute

// maxPasskeyChallenges bounds the challenges waiting for an answer, so
// requests for options can't fill memory.
const maxPasskeyChallenges = 10_000

// passkeyChallenge is one WebAuthn ceremony waiting for the browser.
type passkeyChallenge struct {
	// userID is the account adding a passkey, or finishing its second sign-in
	// step; empty for a sign-in that names no account.
	userID   string
	register bool
	expires  time.Time
}

// passkeyChallenges keeps the challenges handed out, each usable once.
type passkeyChallenges struct {
	mu      sync.Mutex
	pending map[string]passkeyChallenge
}

func (p *passkeyChallenges) add(challenge []byte, entry passkeyChallenge) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.pending == nil {
		p.pending = map[string]passkeyChallenge{}
	}
	for key, value := range p.pending {
		if now.After(value.expires) {
			delete(p.pending, key)
		}
	}
	if len(p.pending) >= maxPasskeyChallenges {
		return errors.New("too many passkey requests at once; try again in a few minutes")
	}
	entry.expires = now.Add(passkeyChallengeLifetime)
	p.pending[string(challenge)] = entry
	return nil
}

// take returns and forgets the challenge, if it is still waiting.
func (p *passkeyChallenges) take(challenge []byte) (passkeyChallenge, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.pending[string(challenge)]
	delete(p.pending, string(challenge))
	if !ok || time.Now().After(entry.expires) {
		return passkeyChallenge{}, false
	}
	return entry, true
}

// relyingParty is the dashboard as passkeys see it: its host name and origin,
// from the address the browser used. Passkeys need a name: browsers refuse
// them on IP addresses, and on certificates they don't trust.
func relyingParty(r *http.Request) (id, origin string, err error) {
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return "", "", errors.New("passkeys need the dashboard on a name, such as dg.example.com, not an IP address; browsers refuse them there")
	}
	return host, "https://" + strings.ToLower(r.Host), nil
}

var b64 = base64.RawURLEncoding

// passkeyOptions are the options for navigator.credentials.create or get, with
// binary values base64url-encoded; the dashboard decodes them.
type passkeyOptions struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rp_id"`
	RPName    string `json:"rp_name,omitempty"`
	// UserID, UserName and DisplayName describe the account, for a registration.
	UserID      string `json:"user_id,omitempty"`
	UserName    string `json:"user_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Algorithms  []int  `json:"algorithms,omitempty"`
	// Credentials are excluded from a registration, or allowed for a second step.
	Credentials []passkeyDescriptor `json:"credentials"`
	Timeout     int                 `json:"timeout"`
}

type passkeyDescriptor struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

func descriptors(keys []store.Passkey) []passkeyDescriptor {
	list := make([]passkeyDescriptor, 0, len(keys))
	for _, key := range keys {
		list = append(list, passkeyDescriptor{ID: b64.EncodeToString(key.CredentialID), Transports: key.Transports})
	}
	return list
}

func decodeField(value, name string) ([]byte, error) {
	data, err := b64.DecodeString(strings.TrimRight(value, "="))
	if err != nil || len(data) == 0 {
		return nil, errors.New("the browser's response is missing " + name)
	}
	return data, nil
}

// startPasskey hands out the options to add a passkey to the signed-in account.
func (s *Server) startPasskey(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	rpID, _, err := relyingParty(r)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	keys, err := store.Passkeys(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(keys) >= store.MaxPasskeys {
		writeError(w, http.StatusConflict, store.ErrTooManyPasskeys)
		return
	}
	challenge, err := webauthn.NewChallenge()
	if err == nil {
		err = s.passkeys.add(challenge, passkeyChallenge{userID: user.ID, register: true})
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyOptions{
		Challenge: b64.EncodeToString(challenge), RPID: rpID, RPName: "DeaconGuard",
		UserID: b64.EncodeToString([]byte(user.ID)), UserName: user.Username, DisplayName: user.Username,
		Algorithms: webauthn.Algorithms, Credentials: descriptors(keys), Timeout: int(passkeyChallengeLifetime / time.Millisecond),
	})
}

type passkeyRegistrationRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	// From navigator.credentials.create: the credential's ID, and its
	// response's clientDataJSON, getAuthenticatorData(), getPublicKey() and
	// getPublicKeyAlgorithm(), base64url-encoded.
	ID                string   `json:"id"`
	ClientDataJSON    string   `json:"client_data_json"`
	AuthenticatorData string   `json:"authenticator_data"`
	PublicKey         string   `json:"public_key"`
	Algorithm         int      `json:"algorithm"`
	Transports        []string `json:"transports"`
}

// addPasskey saves a new passkey after checking the browser's answer. Like
// replacing the authenticator app, it needs the password: a passkey is a
// lasting way in.
func (s *Server) addPasskey(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request passkeyRegistrationRequest
	if !readJSON(w, r, &request) {
		return
	}
	if !s.checkOwnPassword(w, r, user, request.Password) {
		return
	}
	rpID, origin, err := relyingParty(r)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	fields := map[string][]byte{}
	for name, value := range map[string]string{"the credential ID": request.ID, "its client data": request.ClientDataJSON,
		"its authenticator data": request.AuthenticatorData, "its public key": request.PublicKey} {
		if fields[name], err = decodeField(value, name); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	challenge, err := challengeOf(fields["its client data"])
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := s.passkeys.take(challenge)
	if !ok || !pending.register || pending.userID != user.ID {
		writeError(w, http.StatusBadRequest, errors.New("this passkey request has expired; add the passkey again"))
		return
	}
	registration, err := webauthn.VerifyRegistration(webauthn.Ceremony{Challenge: challenge, RPID: rpID, Origin: origin},
		fields["its client data"], fields["its authenticator data"], fields["the credential ID"], fields["its public key"], request.Algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var transports []string
	for _, transport := range request.Transports {
		if len(transports) < 8 && len(transport) <= 32 {
			transports = append(transports, transport)
		}
	}
	key, err := store.AddPasskey(store.Passkey{UserID: user.ID, CredentialID: registration.CredentialID, PublicKey: registration.PublicKey,
		Algorithm: registration.Algorithm, SignCount: registration.SignCount, Name: request.Name, Transports: transports})
	if errors.Is(err, store.ErrPasskeyExists) || errors.Is(err, store.ErrTooManyPasskeys) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.passkey_add", user.Username, key.Name)
	writeJSON(w, http.StatusCreated, key)
}

// challengeOf reads the challenge a browser's client data answers, to find
// the ceremony; webauthn checks the rest.
func challengeOf(clientDataJSON []byte) ([]byte, error) {
	var data struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientDataJSON, &data); err != nil || data.Challenge == "" {
		return nil, errors.New("the browser's response can't be read")
	}
	return b64.DecodeString(data.Challenge)
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	keys, err := store.Passkeys(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &request) {
		return
	}
	err := store.RenamePasskey(user.ID, r.PathValue("id"), request.Name)
	if errors.Is(err, store.ErrUnknownPasskey) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, "user.passkey_rename", user.Username, strings.TrimSpace(request.Name))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) removePasskey(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	keys, err := store.Passkeys(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	name := ""
	for _, key := range keys {
		if key.ID == r.PathValue("id") {
			name = key.Name
		}
	}
	err = store.RemovePasskey(user.ID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrUnknownPasskey):
		writeError(w, http.StatusNotFound, err)
		return
	case errors.Is(err, store.ErrLastTwoStep):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.passkey_remove", user.Username, name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// startPasskeyLogin hands out the options to sign in with a passkey: any of
// this site's passkeys on the first step, or the account's own on the
// second step after its password.
func (s *Server) startPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeError(w, http.StatusConflict, errors.New("sign-in is only used when DeaconGuard serves on the network"))
		return
	}
	if s.limiter.blocked("login", remoteIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many failed sign-in attempts; try again in a few minutes"))
		return
	}
	rpID, _, err := relyingParty(r)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	entry := passkeyChallenge{}
	credentials := []passkeyDescriptor{}
	if user, session, err := sessionUser(r); err == nil && session.Stage == store.StageMFA {
		keys, err := store.Passkeys(user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if len(keys) == 0 {
			writeError(w, http.StatusConflict, errors.New("your account has no passkey; use the code from your authenticator app"))
			return
		}
		entry.userID, credentials = user.ID, descriptors(keys)
	}
	challenge, err := webauthn.NewChallenge()
	if err == nil {
		err = s.passkeys.add(challenge, entry)
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyOptions{Challenge: b64.EncodeToString(challenge), RPID: rpID, Credentials: credentials,
		Timeout: int(passkeyChallengeLifetime / time.Millisecond)})
}

type passkeyLoginRequest struct {
	// From navigator.credentials.get, base64url-encoded.
	ID                string `json:"id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

// passkeyLogin signs in with a passkey. User verification is required, so a
// passkey is two steps by itself: it gives a full session, with no code.
func (s *Server) passkeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeError(w, http.StatusConflict, errors.New("sign-in is only used when DeaconGuard serves on the network"))
		return
	}
	remote := remoteIP(r)
	if s.limiter.blocked("login", remote) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many failed sign-in attempts; try again in a few minutes"))
		return
	}
	var request passkeyLoginRequest
	if !readJSON(w, r, &request) {
		return
	}
	rpID, origin, err := relyingParty(r)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	fields := map[string][]byte{}
	for name, value := range map[string]string{"the credential ID": request.ID, "its client data": request.ClientDataJSON,
		"its authenticator data": request.AuthenticatorData, "its signature": request.Signature} {
		if fields[name], err = decodeField(value, name); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	challenge, err := challengeOf(fields["its client data"])
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := s.passkeys.take(challenge)
	if !ok || pending.register {
		writeError(w, http.StatusBadRequest, errors.New("this sign-in request has expired; try again"))
		return
	}
	fail := func(username, detail string, err error) {
		s.limiter.fail("login", remote)
		store.Audit(username, "user.login_failed", "", detail, remote)
		writeError(w, http.StatusUnauthorized, err)
	}
	key, err := store.PasskeyByCredential(fields["the credential ID"])
	if errors.Is(err, store.ErrUnknownPasskey) {
		fail("", "unknown passkey", err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := store.GetUser(key.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if pending.userID != "" && pending.userID != user.ID {
		fail(user.Username, "passkey of another account", errors.New("this passkey belongs to another account; use your own"))
		return
	}
	count, err := webauthn.VerifyAssertion(webauthn.Ceremony{Challenge: challenge, RPID: rpID, Origin: origin},
		fields["its client data"], fields["its authenticator data"], fields["its signature"], key.PublicKey, key.Algorithm, key.SignCount)
	if err != nil {
		fail(user.Username, "passkey: "+err.Error(), err)
		return
	}
	if user.Disabled {
		store.Audit(user.Username, "user.login_failed", "", "account disabled", remote)
		writeError(w, http.StatusForbidden, store.ErrAccountDisabled)
		return
	}
	if err := store.UsedPasskey(key.ID, count); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = store.DeleteSession(cookie.Value)
	}
	token, session, err := store.CreateSession(user.ID, store.StageFull, remote, r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, token, session)
	store.MarkSignedIn(user.ID)
	store.Audit(user.Username, "user.login", "", "with passkey "+key.Name, remote)
	response, err := s.sessionFor(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
