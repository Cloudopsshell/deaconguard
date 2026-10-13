package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"deaconguard/internal/store"
)

func (s *Server) getSLA(w http.ResponseWriter, r *http.Request) {
	sla, err := store.GetSLA()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, sla)
}

func (s *Server) updateSLA(w http.ResponseWriter, r *http.Request) {
	var sla store.SLA
	if !readJSON(w, r, &sla) {
		return
	}
	if err := store.SetSLA(sla); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	detail := "off"
	if sla.Enabled {
		detail = fmt.Sprintf("known exploited %d days, critical %d, high %d, medium %d, low %d", sla.Exploited, sla.Critical, sla.High, sla.Medium, sla.Low)
	}
	s.audit(r, "settings.sla", "fix deadlines", detail)
	writeJSON(w, http.StatusOK, sla)
}

func (s *Server) listMaintenance(w http.ResponseWriter, r *http.Request) {
	windows, err := store.MaintenanceWindows(time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, windows)
}

type maintenanceRequest struct {
	Name      string   `json:"name"`
	Tags      []string `json:"tags"`
	StartsAt  string   `json:"starts_at"`
	EndsAt    string   `json:"ends_at"`
	SkipScans bool     `json:"skip_scans"`
}

func (s *Server) addMaintenance(w http.ResponseWriter, r *http.Request) {
	var request maintenanceRequest
	if !readJSON(w, r, &request) {
		return
	}
	window, err := store.AddMaintenanceWindow(store.MaintenanceWindow{Name: request.Name, Tags: request.Tags, StartsAt: request.StartsAt,
		EndsAt: request.EndsAt, SkipScans: request.SkipScans, CreatedBy: s.actor(r)}, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	scope := "every host"
	if len(window.Tags) > 0 {
		scope = "hosts tagged " + strings.Join(window.Tags, ", ")
	}
	s.audit(r, "maintenance.add", window.Name, fmt.Sprintf("%s to %s, %s, skip scans: %t", window.StartsAt, window.EndsAt, scope, window.SkipScans))
	writeJSON(w, http.StatusCreated, window)
}

func (s *Server) deleteMaintenance(w http.ResponseWriter, r *http.Request) {
	window, err := store.DeleteMaintenanceWindow(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "maintenance.remove", window.Name, window.Status)
	writeJSON(w, http.StatusOK, window)
}
