package server

import (
	"bytes"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/store"
)

func finishedAudit(t *testing.T, s *Server, hostID string) store.Scan {
	t.Helper()
	record := decode[store.Scan](t, request(t, s, http.MethodPost, "/api/hosts/"+hostID+"/audits", map[string]any{}))
	s.runner.wait()
	return record
}

func TestReportsAreFrozenDownloadedAndVerified(t *testing.T) {
	s := newTestServer(t, auditReport)
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	first := finishedAudit(t, s, host.ID)
	second := finishedAudit(t, s, host.ID)

	if saved := request(t, s, http.MethodPut, "/api/settings/reports", map[string]string{"company": "CloudOpsShell Ltd", "contact": "security@example.com"}); saved.Code != http.StatusOK {
		t.Fatalf("branding: %d %s", saved.Code, saved.Body.String())
	}
	created := request(t, s, http.MethodPost, "/api/reports", map[string]string{"scan_id": second.ID, "client": "Acme Corp", "notes": "Handover", "compare_with": "previous"})
	record := decode[store.ReportRecord](t, created)
	if created.Code != http.StatusCreated || record.Kind != "audit" || len(record.Fingerprint) != 64 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	_, built, err := loadReport(record.ID)
	if err != nil || built.Comparison == nil || built.Comparison.ScanID != first.ID || built.Branding.Company != "CloudOpsShell Ltd" || built.Client != "Acme Corp" {
		t.Fatalf("report = %+v, %v", built.Comparison, err)
	}

	for format, prefix := range map[string]string{"pdf": "%PDF-", "html": "<!doctype html>", "csv": "Type,", "xlsx": "PK", "json": "{"} {
		download := request(t, s, http.MethodGet, "/api/reports/"+record.ID+"/download?format="+format, nil)
		if download.Code != http.StatusOK || !strings.HasPrefix(download.Body.String(), prefix) ||
			!strings.Contains(download.Header().Get("Content-Disposition"), "deaconguard-audit-") {
			t.Fatalf("%s: %d %q", format, download.Code, download.Header().Get("Content-Disposition"))
		}
	}
	if bad := request(t, s, http.MethodGet, "/api/reports/"+record.ID+"/download?format=exe", nil); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown format: %d", bad.Code)
	}

	// Accepting a risk later changes new reports, not this one.
	request(t, s, http.MethodPost, "/api/exceptions", map[string]any{"host_id": host.ID, "control_id": "ACC-02", "reason": "kiosk"})
	if _, again, _ := loadReport(record.ID); again.Audit.Grade != built.Audit.Grade {
		t.Fatal("a report changed after it was made")
	}

	genuine := decode[verifyResponse](t, request(t, s, http.MethodPost, "/api/reports/verify", map[string]string{
		"report_id": record.ID, "fingerprint": strings.ToUpper(record.Fingerprint[:4]) + " " + record.Fingerprint[4:]}))
	if !genuine.Valid || genuine.Grade == "" {
		t.Fatalf("genuine = %+v", genuine)
	}
	tampered := decode[verifyResponse](t, request(t, s, http.MethodPost, "/api/reports/verify", map[string]string{"report_id": record.ID, "fingerprint": strings.Repeat("0", 64)}))
	unknown := decode[verifyResponse](t, request(t, s, http.MethodPost, "/api/reports/verify", map[string]string{"report_id": strings.Repeat("a", 32), "fingerprint": record.Fingerprint}))
	if tampered.Valid || unknown.Valid {
		t.Fatalf("tampered %+v unknown %+v", tampered, unknown)
	}

	if listed := decode[[]store.ReportRecord](t, request(t, s, http.MethodGet, "/api/reports?scan_id="+second.ID, nil)); len(listed) != 1 {
		t.Fatalf("listed %d", len(listed))
	}
	if deleted := request(t, s, http.MethodDelete, "/api/reports/"+record.ID, nil); deleted.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", deleted.Code)
	}
}

func TestShareLinksOpenWithoutSignInUntilRevoked(t *testing.T) {
	s := newTestServer(t, auditReport)
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	audited := finishedAudit(t, s, host.ID)
	record := decode[store.ReportRecord](t, request(t, s, http.MethodPost, "/api/reports", map[string]string{"scan_id": audited.ID}))
	if refused := request(t, s, http.MethodPost, "/api/reports/"+record.ID+"/shares", map[string]int{"days": 7}); refused.Code != http.StatusConflict {
		t.Fatalf("share in local mode: %d", refused.Code)
	}
	// Links are made on a network server; how they open doesn't depend on that.
	_, token, err := store.CreateShare(record.ID, 7*24*time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	path := "/share/" + token
	page := request(t, s, http.MethodGet, path, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Server audit report") || page.Header().Get("Content-Security-Policy") != sharePolicy {
		t.Fatalf("share page: %d %q", page.Code, page.Header().Get("Content-Security-Policy"))
	}
	if pdf := request(t, s, http.MethodGet, path+"/report.pdf", nil); pdf.Code != http.StatusOK || !strings.HasPrefix(pdf.Body.String(), "%PDF-") {
		t.Fatalf("share PDF: %d", pdf.Code)
	}
	shares := decode[[]store.Share](t, request(t, s, http.MethodGet, "/api/reports/"+record.ID+"/shares", nil))
	if len(shares) != 1 || shares[0].Views != 1 {
		t.Fatalf("shares = %+v", shares)
	}
	request(t, s, http.MethodDelete, "/api/shares/"+shares[0].ID, nil)
	if gone := request(t, s, http.MethodGet, path, nil); gone.Code != http.StatusNotFound || !strings.Contains(gone.Body.String(), "no longer works") {
		t.Fatalf("revoked: %d", gone.Code)
	}
	if wrong := request(t, s, http.MethodGet, "/share/not-a-token", nil); wrong.Code != http.StatusNotFound {
		t.Fatalf("wrong token: %d", wrong.Code)
	}
}

func TestLogoMustBeASmallImage(t *testing.T) {
	s := newTestServer(t, auditReport)
	var logo bytes.Buffer
	png.Encode(&logo, image.NewRGBA(image.Rect(0, 0, 120, 40)))
	upload := func(body []byte, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:7480/api/settings/reports/logo", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		s.ServeHTTP(recorder, req)
		return recorder
	}
	if saved := upload(logo.Bytes(), "image/png"); saved.Code != http.StatusOK || !decode[brandingResponse](t, saved).HasLogo {
		t.Fatalf("upload: %d %s", saved.Code, saved.Body.String())
	}
	if text := upload([]byte("<svg/>"), "image/png"); text.Code != http.StatusBadRequest {
		t.Fatalf("not an image: %d", text.Code)
	}
	if svg := upload([]byte("<svg/>"), "image/svg+xml"); svg.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("svg: %d", svg.Code)
	}
	if large := upload(bytes.Repeat([]byte{0}, 400<<10), "image/png"); large.Code < 400 {
		t.Fatalf("too large: %d", large.Code)
	}
	if got := request(t, s, http.MethodGet, "/api/settings/reports/logo", nil); got.Code != http.StatusOK || got.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("logo: %d", got.Code)
	}
}
