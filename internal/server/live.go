package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/live"
	"deaconguard/internal/notify"
	"deaconguard/internal/store"
)

// liveAlertsShown is how many alerts a host's Runtime tab lists.
const liveAlertsShown = 200

// agentLive takes an agent's live detection report, POST /agent/v1/live,
// and answers whether detection should run and whether a test is waiting.
func (h *agentHub) agentLive(w http.ResponseWriter, r *http.Request, host store.Host) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var report agentapi.LiveReport
	if !readJSON(w, r, &report) {
		return
	}
	if len(report.Alerts) > agentapi.MaxLiveAlerts {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("send at most %d alerts at a time", agentapi.MaxLiveAlerts))
		return
	}
	previous, err := store.SaveLiveReport(host.ID, report.Status, report.Alerts, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	enabled, test, err := store.LiveSettings(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if test && enabled {
		_ = store.TakeLiveTest(host.ID)
	}
	if h.onLive != nil {
		h.onLive(host, previous, report.Status, report.Alerts)
	}
	writeJSON(w, http.StatusOK, agentapi.LiveReply{Enabled: enabled, Test: test && enabled})
}

// liveReported logs and notifies what an agent's report brought: alerts,
// and detection stopping.
func (s *Server) liveReported(host store.Host, previous string, status live.Status, alerts []live.Alert) {
	if status.State != "" && status.State != previous {
		switch status.State {
		case live.StateActive:
			serverLog(host.ID, store.LogInfo, "Live detection is active on %s", host.Address)
		case live.StateStopped, live.StateUnsupported:
			serverLog(host.ID, store.LogWarning, "Live detection isn't running on %s: %s", host.Address, status.Reason)
		}
		if previous == live.StateActive && status.State == live.StateStopped {
			s.liveStopped(host, status.Reason)
		}
	}
	var real []live.Alert
	for _, alert := range alerts {
		if alert.Test {
			serverLog(host.ID, store.LogInfo, "Test alert from %s: live detection works end to end", host.Address)
			s.emit(notify.Message{Event: notify.EventRuntime, Level: notify.LevelInfo,
				Title: host.Address + ": test alert, live detection works",
				Lines: []string{"Someone asked for a test alert on the host's Runtime tab: the kernel saw the test program start, the agent's rule matched, and this message came through."},
				Link:  link("/hosts/" + host.ID + "?tab=runtime"), HostID: host.ID, Host: host.Address, Data: map[string]any{"test": true}})
			continue
		}
		serverLog(host.ID, store.LogWarning, "Live detection on %s: %s (%s, %s)", host.Address, alert.Title, alert.Severity, alert.Rule)
		real = append(real, alert)
	}
	if len(real) == 0 {
		return
	}
	level := notify.LevelWarning
	lines := make([]string, 0, len(real))
	data := make([]map[string]any, 0, len(real))
	for index, alert := range real {
		if strings.EqualFold(alert.Severity, "CRITICAL") {
			level = notify.LevelCritical
		}
		if index < 10 {
			line := fmt.Sprintf("%s: %s", strings.ToUpper(alert.Severity), alert.Title)
			if who := alertWho(alert); who != "" {
				line += " (" + who + ")"
			}
			lines = append(lines, line)
		}
		data = append(data, map[string]any{"rule": alert.Rule, "severity": alert.Severity, "title": alert.Title, "program": alert.Program,
			"parent": alert.Parent, "user": alert.User, "path": alert.Path, "command": alert.Command})
	}
	if len(real) > 10 {
		lines = append(lines, fmt.Sprintf("And %d more on the host's Runtime tab.", len(real)-10))
	}
	title := host.Address + ": " + real[0].Title
	if len(real) > 1 {
		title += fmt.Sprintf(", and %s", plural(len(real)-1, "more alert", "more alerts"))
	}
	s.emit(notify.Message{Event: notify.EventRuntime, Level: level, Title: title, Lines: lines,
		Link: link("/hosts/" + host.ID + "?tab=runtime"), HostID: host.ID, Host: host.Address, Data: map[string]any{"alerts": data}})
}

// alertWho says which program did it, as whom.
func alertWho(alert live.Alert) string {
	var parts []string
	if alert.Program != "" {
		parts = append(parts, alert.Program)
	}
	if alert.User != "" {
		parts = append(parts, "as "+alert.User)
	}
	return strings.Join(parts, " ")
}

// liveStopped notifies that live detection stopped on a host where it was
// running.
func (s *Server) liveStopped(host store.Host, reason string) {
	serverLog(host.ID, store.LogWarning, "Live detection stopped on %s: %s", host.Address, reason)
	s.emit(notify.Message{Event: notify.EventRuntimeStopped, Level: notify.LevelWarning,
		Title: host.Address + ": live detection stopped",
		Lines: []string{"Reason: " + reason + ".", "Until it runs again, attacks on this machine aren't seen as they happen. Its Runtime tab shows when it's back."},
		Link:  link("/hosts/" + host.ID + "?tab=runtime"), HostID: host.ID, Host: host.Address, Data: map[string]any{"reason": reason}})
}

type liveResponse struct {
	Status *store.LiveStatus `json:"status"`
	Alerts []store.LiveAlert `json:"alerts"`
}

// getLive serves a host's live detection: GET /api/hosts/{id}/live.
func (s *Server) getLive(w http.ResponseWriter, r *http.Request) {
	host, err := store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	status, err := store.HostLive(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	alerts := []store.LiveAlert{}
	if !host.IsCluster() {
		if alerts, err = store.LiveAlerts(host.ID, liveAlertsShown); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, liveResponse{Status: status, Alerts: alerts})
}

type setLiveRequest struct {
	Enabled *bool `json:"enabled"`
}

// setLive turns live detection on or off: PUT /api/hosts/{id}/live.
func (s *Server) setLive(w http.ResponseWriter, r *http.Request) {
	var request setLiveRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Enabled == nil {
		writeError(w, http.StatusBadRequest, errors.New("enabled is required"))
		return
	}
	host, err := store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err := store.SetLiveEnabled(host.ID, *request.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	state := "off"
	if *request.Enabled {
		state = "on"
	}
	s.audit(r, "host.live", host.Address, "live detection: "+state)
	serverLog(host.ID, store.LogInfo, "%s turned live detection %s for %s", s.actor(r), state, host.Address)
	s.getLive(w, r)
}

// testLive asks the host's agent for a test alert: POST /api/hosts/{id}/live/test.
func (s *Server) testLive(w http.ResponseWriter, r *http.Request) {
	host, err := store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	status, err := store.HostLive(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if status == nil || host.IsCluster() || status.State != live.StateActive {
		writeError(w, http.StatusConflict, errors.New("live detection isn't active on this host, so it can't send a test alert"))
		return
	}
	if err := store.AskLiveTest(host.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "host.live_test", host.Address, "test alert")
	w.WriteHeader(http.StatusAccepted)
}
