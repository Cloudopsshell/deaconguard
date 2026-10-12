package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	_ "image/jpeg" // logos may be JPEG
	_ "image/png"  // or PNG
	"io"
	"net/http"
	"strings"
	"time"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/compliance"
	"deaconguard/internal/report"
	"deaconguard/internal/store"
)

// Download formats, by file extension.
var reportFormats = map[string]string{
	"pdf":  "application/pdf",
	"html": "text/html; charset=utf-8",
	"csv":  "text/csv; charset=utf-8",
	"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"json": "application/json",
}

type createReportRequest struct {
	ScanID string `json:"scan_id"`
	Client string `json:"client"`
	Notes  string `json:"notes"`
	// CompareWith is an earlier audit of the same host, "previous" for the
	// one before this, or empty for none.
	CompareWith string `json:"compare_with"`
	// Frameworks to include a compliance mapping for, such as pci-dss-4.
	Frameworks []string `json:"frameworks"`
}

// createReport freezes an audit or scan as a report, which every download
// format is then rendered from.
func (s *Server) createReport(w http.ResponseWriter, r *http.Request) {
	var request createReportRequest
	if !readJSON(w, r, &request) {
		return
	}
	if len(request.Client) > 200 || len(request.Notes) > 2000 {
		writeError(w, http.StatusBadRequest, errors.New("the client name or notes are too long"))
		return
	}
	scan, err := store.GetScan(request.ScanID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("no such scan"))
		return
	}
	if scan.Status != store.ScanSucceeded {
		writeError(w, http.StatusConflict, errors.New("only a finished scan or audit can be reported"))
		return
	}
	host, err := store.GetHost(scan.HostID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	raw, err := store.GetReport(scan.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	branding, err := store.GetReportBranding()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	id, err := store.NewReportID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for _, framework := range request.Frameworks {
		if _, known := compliance.Find(framework); !known {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unknown framework %q", framework))
			return
		}
	}
	source := report.Source{ID: id, Scan: scan, Host: host, Report: raw, Client: request.Client, Notes: request.Notes, By: s.actor(r), Frameworks: request.Frameworks,
		Now: time.Now(), Version: buildinfo.Version,
		Branding: report.Branding{Company: branding.Company, Contact: branding.Contact, Logo: branding.Logo, LogoType: branding.LogoType}}
	if scan.Audit {
		summary, err := gradeAudit(scan)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		source.Summary = &summary
		if base, err := baseAudit(scan, request.CompareWith); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		} else if base != nil {
			baseSummary, err := gradeAudit(*base)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			source.Base, source.BaseSummary = base, &baseSummary
		}
	}
	built, err := report.Build(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	snapshot, fingerprint, err := report.Snapshot(built)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	record := store.ReportRecord{ID: id, ScanID: scan.ID, HostID: host.ID, Kind: built.Kind, Client: built.Client, CreatedBy: built.GeneratedBy,
		CreatedAt: built.GeneratedAt.Format(time.RFC3339), Fingerprint: fingerprint}
	if err := store.SaveReportSnapshot(record, snapshot); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	detail := host.Address
	if built.Client != "" {
		detail += " for " + built.Client
	}
	s.audit(r, "report.create", host.Address, built.Kind+" report "+id[:8]+", "+detail)
	writeJSON(w, http.StatusCreated, record)
}

// baseAudit finds the audit a report compares with.
func baseAudit(scan store.Scan, compareWith string) (*store.Scan, error) {
	if compareWith == "" {
		return nil, nil
	}
	audits, err := store.ListAudits(scan.HostID, 200)
	if err != nil {
		return nil, err
	}
	if compareWith == "previous" {
		// Audits come newest first: the previous one is the next finished
		// audit after this one in the list.
		seen := false
		for _, candidate := range audits {
			if candidate.ID == scan.ID {
				seen = true
				continue
			}
			if seen && candidate.Status == store.ScanSucceeded {
				return &candidate, nil
			}
		}
		return nil, nil
	}
	for _, candidate := range audits {
		if candidate.ID == compareWith && candidate.ID != scan.ID && candidate.Status == store.ScanSucceeded {
			return &candidate, nil
		}
	}
	return nil, errors.New("compare with a finished audit of the same host")
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	records, err := store.ListReports(r.URL.Query().Get("scan_id"), r.URL.Query().Get("host_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, records)
}

// loadReport reads a frozen report back.
func loadReport(id string) (store.ReportRecord, report.Report, error) {
	record, snapshot, err := store.GetReportSnapshot(id)
	if err != nil {
		return store.ReportRecord{}, report.Report{}, err
	}
	var built report.Report
	if err := json.Unmarshal(snapshot, &built); err != nil {
		return store.ReportRecord{}, report.Report{}, err
	}
	return record, built, nil
}

// render produces one format of a report.
func render(built report.Report, fingerprint, format string, downloads ...report.Link) ([]byte, error) {
	switch format {
	case "pdf":
		return report.PDF(built, fingerprint)
	case "html":
		return report.HTML(built, fingerprint, downloads...)
	case "csv":
		return report.CSV(built)
	case "xlsx":
		return report.XLSX(built, fingerprint)
	case "json":
		return report.JSON(built, fingerprint)
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

func writeDownload(w http.ResponseWriter, built report.Report, format string, contents []byte) {
	header := w.Header()
	header.Set("Content-Type", reportFormats[format])
	header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", built.FileName(format)))
	header.Set("Cache-Control", "no-store")
	w.Write(contents)
}

func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if _, known := reportFormats[format]; !known {
		writeError(w, http.StatusBadRequest, errors.New("format must be pdf, html, csv, xlsx or json"))
		return
	}
	record, built, err := loadReport(r.PathValue("id"))
	if errors.Is(err, store.ErrUnknownReport) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	contents, err := render(built, record.Fingerprint, format)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "report.download", built.Host, record.ID[:8]+" as "+strings.ToUpper(format))
	writeDownload(w, built, format, contents)
}

func (s *Server) deleteReport(w http.ResponseWriter, r *http.Request) {
	record, built, err := loadReport(r.PathValue("id"))
	if errors.Is(err, store.ErrUnknownReport) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err == nil {
		err = store.DeleteReport(record.ID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "report.delete", built.Host, record.ID[:8])
	w.WriteHeader(http.StatusNoContent)
}

type verifyRequest struct {
	ReportID    string `json:"report_id"`
	Fingerprint string `json:"fingerprint"`
}

type verifyResponse struct {
	Valid   bool                `json:"valid"`
	Message string              `json:"message"`
	Report  *store.ReportRecord `json:"report,omitempty"`
	Host    string              `json:"host,omitempty"`
	Grade   string              `json:"grade,omitempty"`
}

// verifyReport checks a report's ID and fingerprint against what this
// server made.
func (s *Server) verifyReport(w http.ResponseWriter, r *http.Request) {
	var request verifyRequest
	if !readJSON(w, r, &request) {
		return
	}
	id := strings.TrimSpace(request.ReportID)
	fingerprint := strings.ToLower(strings.Join(strings.Fields(request.Fingerprint), ""))
	record, built, err := loadReport(id)
	if errors.Is(err, store.ErrUnknownReport) || (err == nil && !validID(id)) {
		writeJSON(w, http.StatusOK, verifyResponse{Message: "This server has no report with that ID. It was made by another server, or deleted."})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if fingerprint != record.Fingerprint {
		writeJSON(w, http.StatusOK, verifyResponse{Message: "The fingerprint doesn't match. The report was changed after it was made, or the fingerprint was mistyped."})
		return
	}
	response := verifyResponse{Valid: true, Report: &record, Host: built.Host,
		Message: fmt.Sprintf("Genuine. This server made this report on %s.", record.CreatedAt)}
	if built.Audit != nil {
		response.Grade = built.Audit.Grade
	}
	writeJSON(w, http.StatusOK, response)
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, character := range id {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

type createShareRequest struct {
	Days int `json:"days"`
}

type shareResponse struct {
	Share store.Share `json:"share"`
	// URL is shown once; only a hash of its token is stored.
	URL string `json:"url"`
}

// maxShareDays bounds how long a share link lives.
const maxShareDays = 30

func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeError(w, http.StatusConflict, errors.New("share links need DeaconGuard serving on the network; download the report instead"))
		return
	}
	var request createShareRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Days == 0 {
		request.Days = 7
	}
	if request.Days < 1 || request.Days > maxShareDays {
		writeError(w, http.StatusBadRequest, fmt.Errorf("a link lasts 1 to %d days", maxShareDays))
		return
	}
	_, built, err := loadReport(r.PathValue("id"))
	if errors.Is(err, store.ErrUnknownReport) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	share, token, err := store.CreateShare(r.PathValue("id"), time.Duration(request.Days)*24*time.Hour, s.actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "report.share", built.Host, fmt.Sprintf("%s for %d days, until %s", share.ReportID[:8], request.Days, share.ExpiresAt))
	writeJSON(w, http.StatusCreated, shareResponse{Share: share, URL: "https://" + r.Host + "/share/" + token})
}

func (s *Server) listShares(w http.ResponseWriter, r *http.Request) {
	shares, err := store.Shares(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, shares)
}

func (s *Server) revokeShare(w http.ResponseWriter, r *http.Request) {
	share, err := store.RevokeShare(r.PathValue("id"))
	if errors.Is(err, store.ErrUnknownShare) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "report.unshare", share.ReportID[:8], "link "+share.ID[:8])
	writeJSON(w, http.StatusOK, share)
}

// sharePolicy lets a shared report use its own inline styles and logo, and
// nothing else.
const sharePolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var shareGone = template.Must(template.New("gone").Parse(`<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Report unavailable</title>
<style>body{font:16px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#0f172a;max-width:560px;margin:15vh auto;padding:0 24px}p{color:#475569}</style>
<h1>This report link no longer works</h1><p>{{.}} Ask whoever sent it for a new link.</p></html>`))

// openShare shows a shared report, or one of its downloads, without sign-in.
func (s *Server) openShare(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Security-Policy", sharePolicy)
	header.Set("Cache-Control", "no-store")
	header.Set("X-Robots-Tag", "noindex, nofollow")
	remote := remoteIP(r)
	if s.limiter.blocked("share", remote) {
		http.Error(w, "Too many tries; wait a few minutes.", http.StatusTooManyRequests)
		return
	}
	token := r.PathValue("token")
	format := strings.TrimPrefix(r.PathValue("file"), "report.")
	page := format == ""
	if !page {
		if _, known := reportFormats[format]; !known || format == "html" {
			http.NotFound(w, r)
			return
		}
	}
	share, err := store.OpenShare(token, page)
	if errors.Is(err, store.ErrUnknownShare) {
		s.limiter.fail("share", remote)
		header.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		shareGone.Execute(w, "It has expired or was revoked, or the address is incomplete.")
		return
	}
	if err != nil {
		http.Error(w, "The report could not be loaded.", http.StatusInternalServerError)
		return
	}
	record, built, err := loadReport(share.ReportID)
	if err != nil {
		http.Error(w, "The report could not be loaded.", http.StatusInternalServerError)
		return
	}
	if page {
		store.Audit("anonymous", "report.share_view", built.Host, record.ID[:8]+" through a share link", remote)
		base := "/share/" + token + "/report."
		contents, err := report.HTML(built, record.Fingerprint,
			report.Link{URL: template.URL(base + "pdf"), Label: "PDF"}, report.Link{URL: template.URL(base + "xlsx"), Label: "Excel"},
			report.Link{URL: template.URL(base + "csv"), Label: "CSV"}, report.Link{URL: template.URL(base + "json"), Label: "JSON"})
		if err != nil {
			http.Error(w, "The report could not be shown.", http.StatusInternalServerError)
			return
		}
		header.Set("Content-Type", "text/html; charset=utf-8")
		w.Write(contents)
		return
	}
	contents, err := render(built, record.Fingerprint, format)
	if err != nil {
		http.Error(w, "The report could not be made.", http.StatusInternalServerError)
		return
	}
	store.Audit("anonymous", "report.share_download", built.Host, record.ID[:8]+" as "+strings.ToUpper(format), remote)
	writeDownload(w, built, format, contents)
}

type brandingResponse struct {
	Company  string `json:"company"`
	Contact  string `json:"contact"`
	HasLogo  bool   `json:"has_logo"`
	LogoType string `json:"logo_type,omitempty"`
}

func (s *Server) getBranding(w http.ResponseWriter, r *http.Request) {
	branding, err := store.GetReportBranding()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, brandingResponse{Company: branding.Company, Contact: branding.Contact, HasLogo: len(branding.Logo) > 0, LogoType: branding.LogoType})
}

func (s *Server) updateBranding(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Company string `json:"company"`
		Contact string `json:"contact"`
	}
	if !readJSON(w, r, &request) {
		return
	}
	if err := store.SetReportText(strings.TrimSpace(request.Company), strings.TrimSpace(request.Contact)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "settings.reports", "", "company and contact")
	s.getBranding(w, r)
}

func (s *Server) getLogo(w http.ResponseWriter, r *http.Request) {
	branding, err := store.GetReportBranding()
	if err != nil || len(branding.Logo) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", branding.LogoType)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(branding.Logo)
}

// uploadLogo takes the logo as the request body: a PNG or JPEG image.
func (s *Server) uploadLogo(w http.ResponseWriter, r *http.Request) {
	contents, err := io.ReadAll(io.LimitReader(r.Body, report.MaxLogoBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(contents) > report.MaxLogoBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the logo must be at most %d KB", report.MaxLogoBytes>>10))
		return
	}
	config, kind, err := image.DecodeConfig(bytes.NewReader(contents))
	if err != nil || (kind != "png" && kind != "jpeg") {
		writeError(w, http.StatusBadRequest, errors.New("the logo must be a PNG or JPEG image"))
		return
	}
	if config.Width > 4000 || config.Height > 4000 {
		writeError(w, http.StatusBadRequest, errors.New("the logo must be at most 4000 pixels wide and high"))
		return
	}
	if err := store.SetReportLogo(contents, "image/"+kind); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "settings.reports", "", "logo")
	s.getBranding(w, r)
}

func (s *Server) removeLogo(w http.ResponseWriter, r *http.Request) {
	if err := store.SetReportLogo(nil, ""); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "settings.reports", "", "logo removed")
	s.getBranding(w, r)
}
