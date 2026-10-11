package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"deaconguard/internal/store"
	"deaconguard/internal/totp"
)

// totpIssuer names DeaconGuard in authenticator apps.
const totpIssuer = "DeaconGuard"

type accountResponse struct {
	store.User
	Sessions []store.Session `json:"sessions"`
	// MFARequired: every account must use two-step sign-in.
	MFARequired bool `json:"mfa_required"`
}

// account describes the signed-in account to itself: "My account".
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	user, session, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	user, err := store.GetUser(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sessions, err := store.UserSessions(user.ID, session.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	required, err := store.RequireMFA()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, accountResponse{User: user, Sessions: sessions, MFARequired: required})
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// changeOwnPassword sets a new password, which also ends a temporary one,
// and signs out the account's other sessions.
func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	user, session, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request passwordChangeRequest
	if !readJSON(w, r, &request) {
		return
	}
	if !s.checkOwnPassword(w, r, user, request.CurrentPassword) {
		return
	}
	if request.NewPassword == request.CurrentPassword {
		writeError(w, http.StatusBadRequest, errors.New("choose a password different from the current one"))
		return
	}
	if err := store.ChangePassword(user.ID, []byte(request.NewPassword), session.ID, false); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, "user.passwd", user.Username, "own password; other sessions signed out")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// checkOwnPassword confirms a sensitive change with the current password,
// counting failures like sign-in does. It writes the error response itself.
func (s *Server) checkOwnPassword(w http.ResponseWriter, r *http.Request, user store.User, password string) bool {
	remote := remoteIP(r)
	if s.limiter.blocked("login", remote) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many wrong passwords; try again in a few minutes"))
		return false
	}
	if err := store.CheckPassword(user.ID, []byte(password)); errors.Is(err, store.ErrWrongPassword) {
		s.limiter.fail("login", remote)
		writeError(w, http.StatusForbidden, err)
		return false
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}
	return true
}

type mfaStartRequest struct {
	// Password confirms replacing an authenticator that is already set up.
	Password string `json:"password"`
}

type mfaStartResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// startMFA creates a new authenticator secret to scan. It is used only after
// confirmMFA proves the app has it.
func (s *Server) startMFA(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request mfaStartRequest
	if !readJSON(w, r, &request) {
		return
	}
	if user.MFAEnabled && !s.checkOwnPassword(w, r, user, request.Password) {
		return
	}
	secret, err := store.StartTOTP(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, mfaStartResponse{Secret: secret, URI: totp.URI(totpIssuer, user.Username, secret)})
}

type mfaConfirmRequest struct {
	Code string `json:"code"`
}

type recoveryCodesResponse struct {
	// RecoveryCodes are shown once; only their hashes are kept.
	RecoveryCodes []string `json:"recovery_codes"`
}

// confirmMFA turns on two-step sign-in once a code from the new
// authenticator matches, and returns the recovery codes.
func (s *Server) confirmMFA(w http.ResponseWriter, r *http.Request) {
	user, session, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request mfaConfirmRequest
	if !readJSON(w, r, &request) {
		return
	}
	codes, err := store.ConfirmTOTP(user.ID, request.Code, time.Now())
	if errors.Is(err, store.ErrWrongCode) || errors.Is(err, store.ErrNoPendingSetup) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	action := "set up"
	if user.MFAEnabled {
		action = "replaced the authenticator; other sessions signed out"
		_, _ = store.EndSessions(user.ID, "", session.ID)
	}
	s.audit(r, "user.mfa_enable", user.Username, action)
	writeJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

type passwordConfirmRequest struct {
	Password string `json:"password"`
}

// removeOwnMFA turns off the account's two-step sign-in, unless every
// account must use it.
func (s *Server) removeOwnMFA(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request passwordConfirmRequest
	if !readJSON(w, r, &request) {
		return
	}
	if required, err := store.RequireMFA(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	} else if required {
		writeError(w, http.StatusConflict, store.ErrMFARequired)
		return
	}
	if !s.checkOwnPassword(w, r, user, request.Password) {
		return
	}
	if err := store.RemoveMFA(user.ID, false); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.mfa_disable", user.Username, "own")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// newRecoveryCodes replaces the account's recovery codes.
func (s *Server) newRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	var request passwordConfirmRequest
	if !readJSON(w, r, &request) {
		return
	}
	if !user.MFAEnabled {
		writeError(w, http.StatusConflict, errors.New("set up two-step sign-in first"))
		return
	}
	if !s.checkOwnPassword(w, r, user, request.Password) {
		return
	}
	codes, err := store.NewRecoveryCodes(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.recovery_codes", user.Username, "new recovery codes")
	writeJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}

// endOwnSession signs out one of the account's sessions, or all the others
// when the ID is "others".
func (s *Server) endOwnSession(w http.ResponseWriter, r *http.Request) {
	user, session, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
		return
	}
	id := r.PathValue("id")
	if id == session.ID {
		writeError(w, http.StatusBadRequest, errors.New("to end this session, sign out"))
		return
	}
	if id == "others" {
		id = ""
	}
	ended, err := store.EndSessions(user.ID, id, session.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.sessions_end", user.Username, fmt.Sprintf("%d signed out", ended))
	writeJSON(w, http.StatusOK, map[string]int64{"ended": ended})
}

// networkOnly refuses account management in local mode, which has no
// accounts or sign-in.
func (s *Server) networkOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.network {
			writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network"))
			return
		}
		next(w, r)
	}
}

// listUsers is the Accounts page.
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	required, err := store.RequireMFA()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "mfa_required": required})
}

type newUserRequest struct {
	Username string `json:"username"`
	// Password is temporary: it must be changed at the first sign-in.
	Password string `json:"password"`
	// Role defaults to viewer, the least access.
	Role string `json:"role"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var request newUserRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Role == "" {
		request.Role = store.RoleViewer
	}
	user, err := store.AddUser(strings.TrimSpace(request.Username), []byte(request.Password), request.Role, true)
	if errors.Is(err, store.ErrUserExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, "user.add", user.Username, roleName(user.Role)+"; temporary password")
	writeJSON(w, http.StatusCreated, user)
}

// otherUser returns the account an admin action is for. Admins change their
// own account on My account, so an action can't lock them out by accident.
func (s *Server) otherUser(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	target, err := store.GetUser(r.PathValue("id"))
	if errors.Is(err, store.ErrUnknownUser) {
		writeError(w, http.StatusNotFound, err)
		return store.User{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return store.User{}, false
	}
	if me, _, ok := currentUser(r); ok && me.ID == target.ID {
		writeError(w, http.StatusConflict, errors.New("change your own account on My account"))
		return store.User{}, false
	}
	return target, true
}

// resetUserMFA turns off another account's two-step sign-in, for a lost
// phone, and signs it out everywhere.
func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	target, ok := s.otherUser(w, r)
	if !ok {
		return
	}
	if err := store.RemoveMFA(target.ID, true); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.mfa_reset", target.Username, "signed out everywhere")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type temporaryPasswordRequest struct {
	Password string `json:"password"`
}

// setTemporaryPassword gives another account a password it must change at
// its next sign-in, and signs it out everywhere.
func (s *Server) setTemporaryPassword(w http.ResponseWriter, r *http.Request) {
	target, ok := s.otherUser(w, r)
	if !ok {
		return
	}
	var request temporaryPasswordRequest
	if !readJSON(w, r, &request) {
		return
	}
	if err := store.ChangePassword(target.ID, []byte(request.Password), "", true); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, "user.passwd", target.Username, "temporary password; signed out everywhere")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type userUpdateRequest struct {
	Disabled *bool   `json:"disabled"`
	Role     *string `json:"role"`
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	target, ok := s.otherUser(w, r)
	if !ok {
		return
	}
	var request userUpdateRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Disabled == nil && request.Role == nil {
		writeError(w, http.StatusBadRequest, errors.New("nothing to change"))
		return
	}
	if request.Role != nil && *request.Role != target.Role {
		if err := store.SetRole(target.ID, *request.Role); errors.Is(err, store.ErrLastAccount) {
			writeError(w, http.StatusConflict, err)
			return
		} else if errors.Is(err, store.ErrUnknownRole) {
			writeError(w, http.StatusBadRequest, err)
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.audit(r, "user.role", target.Username, roleName(target.Role)+" to "+roleName(*request.Role)+"; signed out everywhere")
	}
	if request.Disabled == nil || *request.Disabled == target.Disabled {
		updated, err := store.GetUser(target.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, updated)
		return
	}
	if err := store.SetDisabled(target.ID, *request.Disabled); errors.Is(err, store.ErrLastAccount) {
		writeError(w, http.StatusConflict, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	action := "user.enable"
	if *request.Disabled {
		action = "user.disable"
	}
	s.audit(r, action, target.Username, "")
	updated, err := store.GetUser(target.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	target, ok := s.otherUser(w, r)
	if !ok {
		return
	}
	if err := store.RemoveUserID(target.ID); errors.Is(err, store.ErrLastAccount) {
		writeError(w, http.StatusConflict, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "user.remove", target.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

type securitySettings struct {
	RequireMFA bool `json:"require_mfa"`
}

// updateSecurity turns "every account must use two-step sign-in" on or off.
func (s *Server) updateSecurity(w http.ResponseWriter, r *http.Request) {
	var request securitySettings
	if !readJSON(w, r, &request) {
		return
	}
	// Requiring it before using it would send the admin who turned it on
	// straight to setting it up.
	if me, _, ok := currentUser(r); ok && request.RequireMFA && !me.MFAEnabled {
		writeError(w, http.StatusConflict, errors.New("set up two-step sign-in for your own account first, on My account"))
		return
	}
	if err := store.SetRequireMFA(request.RequireMFA); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	state := "off"
	if request.RequireMFA {
		state = "on"
	}
	s.audit(r, "settings.require_mfa", "", state)
	writeJSON(w, http.StatusOK, request)
}

// appearance is the dashboard's mode and theme, which the browser applies;
// the server only checks that they are known values.
type appearance struct {
	Mode  string `json:"mode"`
	Theme string `json:"theme"`
}

var (
	appearanceModes  = map[string]bool{"system": true, "light": true, "dark": true}
	appearanceThemes = map[string]bool{"indigo": true, "ocean": true, "teal": true, "plum": true, "graphite": true}
)

// saveAppearance keeps the account's mode and theme, so they follow it to
// every browser.
func (s *Server) saveAppearance(w http.ResponseWriter, r *http.Request) {
	user, _, ok := currentUser(r)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("accounts are used when DeaconGuard serves on the network; the browser keeps the appearance"))
		return
	}
	var request appearance
	if !readJSON(w, r, &request) {
		return
	}
	if !appearanceModes[request.Mode] || !appearanceThemes[request.Theme] {
		writeError(w, http.StatusBadRequest, errors.New("unknown mode or theme"))
		return
	}
	encoded, _ := json.Marshal(request)
	if err := store.SetAppearance(user.ID, string(encoded)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

// appearanceJSON returns a saved appearance for the session response, or
// nothing when none was saved or it no longer parses.
func appearanceJSON(saved string) json.RawMessage {
	var value appearance
	if saved == "" || json.Unmarshal([]byte(saved), &value) != nil {
		return nil
	}
	return json.RawMessage(saved)
}
