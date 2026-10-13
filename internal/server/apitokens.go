package server

import (
	"errors"
	"net/http"
	"time"

	"deaconguard/internal/store"
)

type createAPITokenRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// Days the token lasts, up to 365; 0 lasts until revoked.
	Days int `json:"days"`
}

type createdAPIToken struct {
	store.APIToken
	// Token is shown once, now.
	Token string `json:"token"`
}

func (s *Server) listOwnAPITokens(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("sign in to DeaconGuard"))
		return
	}
	tokens, err := store.APITokens(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("sign in to DeaconGuard"))
		return
	}
	var request createAPITokenRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Role == "" {
		request.Role = store.RoleViewer
	}
	if request.Days < 0 || request.Days > 365 {
		writeError(w, http.StatusBadRequest, errors.New("a token lasts 1 to 365 days, or 0 for until revoked"))
		return
	}
	token, secret, err := store.CreateAPIToken(user, request.Name, request.Role, time.Duration(request.Days)*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	expires := "never expires"
	if token.ExpiresAt != "" {
		expires = "expires " + token.ExpiresAt
	}
	s.audit(r, "apitoken.create", token.Name, token.Role+", "+expires)
	writeJSON(w, http.StatusCreated, createdAPIToken{APIToken: token, Token: secret})
}

// revokeOwnAPIToken revokes one of the account's tokens; admins revoke any
// with revokeAPIToken.
func (s *Server) revokeOwnAPIToken(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	token, err := store.GetAPIToken(r.PathValue("id"))
	if !ok || err != nil || token.UserID != user.ID {
		writeError(w, http.StatusNotFound, store.ErrUnknownAPIToken)
		return
	}
	s.revoke(w, r, token)
}

func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	token, err := store.GetAPIToken(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.revoke(w, r, token)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, token store.APIToken) {
	revoked, err := store.RevokeAPIToken(token.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "apitoken.revoke", token.Name, "of "+token.Username)
	writeJSON(w, http.StatusOK, revoked)
}

func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := store.APITokens("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}
