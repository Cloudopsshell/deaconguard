package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
	"deaconguard/internal/compliance"
	"deaconguard/internal/policy"
	"deaconguard/internal/store"
)

type startAuditRequest struct {
	// Advanced adds the advanced antivirus scan (YARA) to the audit.
	Advanced bool `json:"advanced"`
}

// startAudit runs a handover audit: every check, graded together.
func (s *Server) startAudit(w http.ResponseWriter, r *http.Request) {
	host, err := store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	var request startAuditRequest
	if !readJSON(w, r, &request) {
		return
	}
	selected := append([]string(nil), audit.Checks...)
	if request.Advanced {
		selected = append(selected, checks.YARA)
	}
	selected, err = checks.Normalize(selected)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if host.Transport == store.TransportAgent && !s.network {
		writeError(w, http.StatusConflict, errors.New("agent hosts are audited when DeaconGuard serves on the network"))
		return
	}
	if err := checkAgentVersion(host, selected); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	record, err := s.runner.start(host, selected, false)
	if errors.Is(err, errScanInProgress) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err == nil {
		err = store.MarkAudit(record.ID)
		record.Audit = true
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if host.Transport == store.TransportAgent {
		s.agents.wake(host.ID)
	}
	s.audit(r, "audit.start", host.Address, strings.Join(selected, ", "))
	serverLog(host.ID, store.LogInfo, "Audit of %s started by %s", host.Address, s.actor(r))
	writeJSON(w, http.StatusAccepted, record)
}

// auditListItem is an audit with its grade, once it has one.
type auditListItem struct {
	store.Scan
	Grade  string `json:"grade,omitempty"`
	Score  int    `json:"score"`
	Failed int    `json:"failed"`
}

func (s *Server) listAudits(w http.ResponseWriter, r *http.Request) {
	audits, err := store.ListAudits(r.URL.Query().Get("host_id"), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	items := make([]auditListItem, 0, len(audits))
	for _, record := range audits {
		item := auditListItem{Scan: record}
		if record.Status == store.ScanSucceeded {
			if summary, err := gradeAudit(record); err == nil {
				item.Grade, item.Score, item.Failed = summary.Grade, summary.Score, summary.Counts.Failed
			}
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

// gradeAudit grades a finished audit with the risks accepted and the
// policies enabled now.
func gradeAudit(record store.Scan) (audit.Summary, error) {
	report, err := store.GetReport(record.ID)
	if err != nil {
		return audit.Summary{}, err
	}
	exceptions, err := store.Exceptions(record.HostID)
	if err != nil {
		return audit.Summary{}, err
	}
	summary, err := audit.Grade(record, report, exceptions, time.Now())
	if err != nil {
		return audit.Summary{}, err
	}
	policies, err := enabledPolicies()
	if err != nil {
		return audit.Summary{}, err
	}
	summary.ApplyPolicies(policies)
	return summary, nil
}

// enabledPolicies parses the policies that are on. A stored policy always
// parsed when it was saved; one that no longer does is skipped.
func enabledPolicies() ([]audit.NamedPolicy, error) {
	records, err := store.ListPolicies()
	if err != nil {
		return nil, err
	}
	var policies []audit.NamedPolicy
	for _, record := range records {
		if !record.Enabled {
			continue
		}
		if parsed, err := policy.Parse([]byte(record.Source)); err == nil {
			policies = append(policies, audit.NamedPolicy{ID: record.ID, Policy: parsed})
		}
	}
	return policies, nil
}

// complianceViews reads an audit framework by framework.
func complianceViews(summary audit.Summary) []compliance.Result {
	var results []compliance.Result
	for _, framework := range compliance.Frameworks() {
		results = append(results, compliance.Evaluate(summary, framework))
	}
	return results
}

type auditDetail struct {
	Scan       store.Scan          `json:"scan"`
	Host       store.Host          `json:"host"`
	Summary    *audit.Summary      `json:"summary,omitempty"`
	Compliance []compliance.Result `json:"compliance,omitempty"`
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	record, err := store.GetScan(r.PathValue("id"))
	if err != nil || !record.Audit {
		writeError(w, http.StatusNotFound, errors.New("no such audit"))
		return
	}
	host, err := store.GetHost(record.HostID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	detail := auditDetail{Scan: record, Host: host}
	if record.Status == store.ScanSucceeded {
		summary, err := gradeAudit(record)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		detail.Summary = &summary
		detail.Compliance = complianceViews(summary)
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	exceptions, err := store.Exceptions(r.URL.Query().Get("host_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, exceptions)
}

type exceptionRequest struct {
	// HostID is empty to accept the risk on every host.
	HostID    string `json:"host_id"`
	ControlID string `json:"control_id"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) addException(w http.ResponseWriter, r *http.Request) {
	var request exceptionRequest
	if !readJSON(w, r, &request) {
		return
	}
	known := false
	for _, id := range checks.BaselineIDs() {
		known = known || id == request.ControlID
	}
	if policies, err := enabledPolicies(); err == nil {
		for _, named := range policies {
			for _, control := range named.Policy.Controls {
				known = known || control.ID == request.ControlID
			}
		}
	}
	if !known {
		writeError(w, http.StatusBadRequest, errors.New("unknown control"))
		return
	}
	exception, err := store.AddException(request.HostID, request.ControlID, request.Reason, request.ExpiresAt, s.actor(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	target := "every host"
	if exception.HostID != "" {
		if host, err := store.GetHost(exception.HostID); err == nil {
			target = host.Address
		}
	}
	detail := exception.ControlID + ": " + exception.Reason
	if exception.ExpiresAt != "" {
		detail += "; until " + exception.ExpiresAt
	}
	s.audit(r, "audit.accept", target, detail)
	writeJSON(w, http.StatusCreated, exception)
}

func (s *Server) removeException(w http.ResponseWriter, r *http.Request) {
	exception, err := store.GetException(r.PathValue("id"))
	if errors.Is(err, store.ErrUnknownException) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err == nil {
		err = store.RemoveException(exception.ID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "audit.unaccept", exception.ControlID, exception.Reason)
	w.WriteHeader(http.StatusNoContent)
}

type auditSettings struct {
	AuditOnEnroll bool `json:"audit_on_enroll"`
}

func (s *Server) getAuditSettings(w http.ResponseWriter, r *http.Request) {
	on, err := store.AuditOnEnroll()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, auditSettings{AuditOnEnroll: on})
}

func (s *Server) updateAuditSettings(w http.ResponseWriter, r *http.Request) {
	var request auditSettings
	if !readJSON(w, r, &request) {
		return
	}
	if err := store.SetAuditOnEnroll(request.AuditOnEnroll); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	state := "off"
	if request.AuditOnEnroll {
		state = "on"
	}
	s.audit(r, "settings.audit_on_enroll", "", state)
	writeJSON(w, http.StatusOK, request)
}
