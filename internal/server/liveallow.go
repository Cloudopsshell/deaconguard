package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/live"
	"deaconguard/internal/store"
)

type liveAllowRequest struct {
	Rule      string `json:"rule"`
	Program   string `json:"program"`
	Path      string `json:"path"`
	Image     string `json:"image"`
	Container string `json:"container"`
	Namespace string `json:"namespace"`
	HostID    string `json:"host_id"`
	Note      string `json:"note"`
}

func (request liveAllowRequest) rule() store.LiveAllow {
	trim := strings.TrimSpace
	return store.LiveAllow{Allow: live.Allow{Rule: trim(request.Rule), Program: trim(request.Program), Path: trim(request.Path),
		Image: trim(request.Image), Container: trim(request.Container), Namespace: trim(request.Namespace)},
		HostID: trim(request.HostID), Note: trim(request.Note)}
}

// describeAllow says what a rule matches, for the audit log.
func describeAllow(rule store.LiveAllow) string {
	parts := []string{rule.Rule}
	for _, field := range []struct{ name, value string }{{"program", rule.Program}, {"path", rule.Path}, {"image", rule.Image},
		{"container", rule.Container}, {"namespace", rule.Namespace}} {
		if field.value != "" {
			parts = append(parts, field.name+" "+field.value)
		}
	}
	scope := "all hosts"
	if rule.HostID != "" {
		scope = rule.HostID
		if host, err := store.GetHost(rule.HostID); err == nil {
			scope = host.Address
		}
	}
	return strings.Join(parts, ", ") + "; on " + scope
}

// listLiveAllow serves the allowlist: GET /api/live/allowlist.
func (s *Server) listLiveAllow(w http.ResponseWriter, r *http.Request) {
	rules, err := store.ListLiveAllow()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// createLiveAllow adds a rule: POST /api/live/allowlist.
func (s *Server) createLiveAllow(w http.ResponseWriter, r *http.Request) {
	var request liveAllowRequest
	if !readJSON(w, r, &request) {
		return
	}
	rule := request.rule()
	id, err := store.CreateLiveAllow(rule, s.actor(r), time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, "live.allow_add", strconv.FormatInt(id, 10), describeAllow(rule))
	serverLog(rule.HostID, store.LogInfo, "%s added a live detection allowlist rule: %s", s.actor(r), describeAllow(rule))
	saved, err := store.GetLiveAllow(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func allowID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, store.ErrLiveAllowNotFound)
		return 0, false
	}
	return id, true
}

// updateLiveAllow changes a rule: PUT /api/live/allowlist/{id}.
func (s *Server) updateLiveAllow(w http.ResponseWriter, r *http.Request) {
	id, ok := allowID(w, r)
	if !ok {
		return
	}
	var request liveAllowRequest
	if !readJSON(w, r, &request) {
		return
	}
	before, err := store.GetLiveAllow(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	rule := request.rule()
	rule.ID = id
	if err := store.UpdateLiveAllow(rule, time.Now()); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrLiveAllowNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err)
		return
	}
	s.audit(r, "live.allow_change", strconv.FormatInt(id, 10), describeAllow(before)+" → "+describeAllow(rule))
	saved, err := store.GetLiveAllow(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// deleteLiveAllow removes a rule: DELETE /api/live/allowlist/{id}.
func (s *Server) deleteLiveAllow(w http.ResponseWriter, r *http.Request) {
	id, ok := allowID(w, r)
	if !ok {
		return
	}
	before, err := store.GetLiveAllow(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err := store.DeleteLiveAllow(id); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "live.allow_remove", strconv.FormatInt(id, 10), describeAllow(before))
	serverLog(before.HostID, store.LogInfo, "%s removed a live detection allowlist rule: %s", s.actor(r), describeAllow(before))
	w.WriteHeader(http.StatusNoContent)
}
