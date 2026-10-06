// Package server provides the web UI, its JSON API, and the agent API.
//
// It runs in one of two modes. Local mode (New) listens on a loopback address
// without sign-in, for one person on this machine. Network mode (NewNetwork)
// serves the dashboard over HTTPS to other machines, requires sign-in, and
// lets agents enroll and run scans.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/buildinfo"
	"deaconguard/internal/checks"
	"deaconguard/internal/local"
	"deaconguard/internal/store"
)

const maxRequestBytes = 64 << 10

type Server struct {
	runner *runner
	agents *agentHub
	// localAvailable reports why this machine cannot be scanned, if it cannot.
	localAvailable func() error
	ui             fs.FS
	handler        http.Handler
	// network is set in network mode; pin is the TLS certificate's public key
	// pin that enrollment tokens carry.
	network bool
	pin     string
	limiter *failureLimiter
}

// New builds the local-mode handler. ui holds the built web app; scan may be
// nil to use the real local scanner.
func New(ui fs.FS, scan scanFunc) (*Server, error) { return newServer(ui, scan, false, "") }

// NewNetwork builds the network-mode handler. pin is the public key pin of the
// certificate the server listens with. At least one user must exist.
func NewNetwork(ui fs.FS, scan scanFunc, pin string) (*Server, error) {
	users, err := store.ListUsers()
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, errors.New("create a dashboard account before serving on the network: deaconguard user add USERNAME")
	}
	return newServer(ui, scan, true, pin)
}

func newServer(ui fs.FS, scan scanFunc, network bool, pin string) (*Server, error) {
	if err := store.InterruptRunningScans(); err != nil {
		return nil, err
	}
	if err := store.PruneAllScans(store.KeepScansPerHost); err != nil {
		return nil, err
	}
	s := &Server{
		runner: newRunner(scan), ui: ui, network: network, pin: pin, limiter: newFailureLimiter(),
		localAvailable: func() error { _, err := local.New(); return err },
	}
	s.agents = newAgentHub(s.runner)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/audit", s.listAudit)
	mux.HandleFunc("GET /api/enrollment-tokens", s.listEnrollmentTokens)
	mux.HandleFunc("POST /api/enrollment-tokens", s.createEnrollmentToken)
	mux.HandleFunc("DELETE /api/enrollment-tokens/{id}", s.revokeEnrollmentToken)
	mux.HandleFunc("GET /api/summary", s.summary)
	mux.HandleFunc("GET /api/hosts", s.listHosts)
	mux.HandleFunc("POST /api/hosts", s.addHost)
	mux.HandleFunc("GET /api/hosts/{id}", s.getHost)
	mux.HandleFunc("PATCH /api/hosts/{id}", s.updateHost)
	mux.HandleFunc("DELETE /api/hosts/{id}", s.removeHost)
	mux.HandleFunc("GET /api/checks", s.listChecks)
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, buildinfo.Get()) })
	mux.HandleFunc("GET /api/capabilities", s.capabilities)
	mux.HandleFunc("POST /api/hosts/{id}/scans", s.startScan)
	mux.HandleFunc("GET /api/scans/{id}", s.getScan)
	mux.HandleFunc("DELETE /api/scans/{id}", s.deleteScan)
	mux.HandleFunc("GET /api/prompts", s.listPrompts)
	mux.HandleFunc("GET /api/activity", s.listActivity)
	mux.HandleFunc("GET /api/scans/{id}/events", s.scanEvents)
	mux.HandleFunc("POST /api/scans/{id}/respond", s.respond)
	mux.HandleFunc("GET /api/vulnerabilities", s.listVulnerabilities)
	mux.HandleFunc("GET /api/vulnerabilities/{cve}", s.getVulnerability)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, errors.New("unknown API endpoint"))
	})
	mux.HandleFunc("/", s.serveUI)
	if network {
		agentMux := http.NewServeMux()
		agentMux.HandleFunc("POST "+agentapi.PathPrefix+"enroll", s.agents.enroll(s.limiter))
		agentMux.HandleFunc("GET "+agentapi.PathPrefix+"job", s.agents.authenticated(s.agents.job))
		agentMux.HandleFunc("POST "+agentapi.PathPrefix+"scans/{id}/events", s.agents.authenticated(s.agents.events))
		agentMux.HandleFunc("POST "+agentapi.PathPrefix+"scans/{id}/result", s.agents.authenticated(s.agents.result))
		agentMux.HandleFunc(agentapi.PathPrefix, func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, errors.New("unknown agent API endpoint"))
		})
		browser := s.signedIn(browserChecks(mux, "https"))
		s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, agentapi.PathPrefix) {
				agentMux.ServeHTTP(w, r)
				return
			}
			browser.ServeHTTP(w, r)
		})
		s.agents.start()
	} else {
		s.handler = localOnly(browserChecks(mux, "http"))
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Close cancels questions waiting for an answer and blocks until background
// scans finish.
func (s *Server) Close() {
	s.agents.stop()
	s.runner.close()
}

// IsLoopback reports whether a listen address only accepts local connections.
func IsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// localOnly rejects requests not addressed to localhost, which blocks DNS
// rebinding in local mode, where there is no sign-in.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoopback(hostWithPort(r.Host)) {
			writeError(w, http.StatusForbidden, errors.New("DeaconGuard only answers requests addressed to localhost"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// browserChecks rejects requests that did not come from a page served by this
// server: the Origin, Fetch Metadata, and JSON content-type checks stop other
// websites from changing data.
func browserChecks(next http.Handler, scheme string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				writeError(w, http.StatusForbidden, errors.New("cross-site requests are not allowed"))
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != scheme+"://"+r.Host {
				writeError(w, http.StatusForbidden, errors.New("cross-origin requests are not allowed"))
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPatch {
				mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if mediaType != "application/json" {
					writeError(w, http.StatusUnsupportedMediaType, errors.New("requests must use Content-Type: application/json"))
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func hostWithPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), "80")
}

type summary struct {
	Hosts            int                     `json:"hosts"`
	ScannedHosts     int                     `json:"scanned_hosts"`
	AttentionHosts   int                     `json:"attention_hosts"`
	Findings         int                     `json:"findings"`
	UniqueCVEs       int                     `json:"unique_cves"`
	Unsupported      int                     `json:"unsupported"`
	StaleFeeds       int                     `json:"stale_feeds"`
	Severity         store.SeverityCounts    `json:"severity"`
	HostSummaries    []store.HostSummary     `json:"host_summaries"`
	Checks           map[string]*checkTotals `json:"checks"`
	TopVulnerability []store.Vulnerability   `json:"top_vulnerabilities"`
}

// checkTotals aggregates each host's latest result for one check.
type checkTotals struct {
	Hosts             int                  `json:"hosts"`
	HostsWithFindings int                  `json:"hosts_with_findings"`
	Incomplete        int                  `json:"incomplete"`
	NotRun            int                  `json:"not_run"`
	Findings          int                  `json:"findings"`
	Severity          store.SeverityCounts `json:"severity"`
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	hosts, err := store.HostSummaries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	vulnerabilities, err := store.Vulnerabilities()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	result := summary{Hosts: len(hosts), UniqueCVEs: len(vulnerabilities), HostSummaries: hosts, Checks: make(map[string]*checkTotals)}
	for _, host := range hosts {
		for id, check := range host.Checks {
			totals := result.Checks[id]
			if totals == nil {
				totals = &checkTotals{}
				result.Checks[id] = totals
			}
			// A skipped or failed check examined nothing, so it must not look clean.
			if check.Status == checks.StatusSkipped || check.Status == checks.StatusFailed {
				totals.NotRun++
				continue
			}
			totals.Hosts++
			totals.Findings += check.FindingCount
			if check.FindingCount > 0 {
				totals.HostsWithFindings++
			}
			if check.Status == checks.StatusPartial {
				totals.Incomplete++
			}
			totals.Severity.Critical += check.Severity.Critical
			totals.Severity.High += check.Severity.High
			totals.Severity.Medium += check.Severity.Medium
			totals.Severity.Low += check.Severity.Low
			totals.Severity.Unknown += check.Severity.Unknown
		}
		if host.LastScan != nil && (host.LastScan.Status == store.ScanFailed || store.IsWaiting(host.LastScan.Status)) {
			result.AttentionHosts++
		}
		if host.LastReport == nil {
			continue
		}
		report := host.LastReport
		result.ScannedHosts++
		result.Findings += report.FindingCount
		result.Unsupported += report.UnsupportedCount
		result.Severity.Critical += report.Severity.Critical
		result.Severity.High += report.Severity.High
		result.Severity.Medium += report.Severity.Medium
		result.Severity.Low += report.Severity.Low
		result.Severity.Unknown += report.Severity.Unknown
		if report.FeedStale {
			result.StaleFeeds++
		}
	}
	if len(vulnerabilities) > 10 {
		vulnerabilities = vulnerabilities[:10]
	}
	result.TopVulnerability = vulnerabilities
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := store.HostSummaries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

type addHostRequest struct {
	// Transport must be "local"; other machines enroll as agents.
	Transport string `json:"transport"`
	AllowSudo bool   `json:"allow_sudo"`
}

type capabilitiesResponse struct {
	// LocalScanning reports whether this server can scan the machine it runs on.
	LocalScanning bool   `json:"local_scanning"`
	LocalReason   string `json:"local_reason,omitempty"`
	Hostname      string `json:"hostname"`
	Username      string `json:"username"`
	// Agents reports whether agents can enroll, which needs network mode.
	Agents bool `json:"agents"`
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	response := capabilitiesResponse{LocalScanning: true, Hostname: local.Hostname(), Username: local.Username(), Agents: s.network}
	if err := s.localAvailable(); err != nil {
		response.LocalScanning, response.LocalReason = false, err.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) addHost(w http.ResponseWriter, r *http.Request) {
	var request addHostRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Transport != "" && request.Transport != store.TransportLocal {
		writeError(w, http.StatusBadRequest, errors.New("only this machine can be added here; other machines join by enrolling an DeaconGuard agent"))
		return
	}
	if err := s.localAvailable(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	host, err := store.AddLocalHost(local.Hostname(), local.Username())
	if errors.Is(err, store.ErrLocalHostExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if request.AllowSudo {
		if host, err = store.SetAllowSudo(host.ID, true); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.audit(r, "host.add", host.Address, "this machine")
	writeJSON(w, http.StatusCreated, host)
}

type updateHostRequest struct {
	AllowSudo *bool `json:"allow_sudo"`
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	var request updateHostRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.AllowSudo == nil {
		writeError(w, http.StatusBadRequest, errors.New("nothing to update"))
		return
	}
	host, err := store.SetAllowSudo(r.PathValue("id"), *request.AllowSudo)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "host.sudo", host.Address, fmt.Sprintf("allow sudo: %t", *request.AllowSudo))
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) listChecks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, checks.Definitions())
}

type hostDetail struct {
	store.HostSummary
	Scans []store.Scan `json:"scans"`
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hosts, err := store.HostSummaries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for _, host := range hosts {
		if host.ID != id {
			continue
		}
		scans, err := store.ListScans(id, store.KeepScansPerHost+len(checks.Definitions()))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, hostDetail{HostSummary: host, Scans: scans})
		return
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("unknown host ID: %s", id))
}

func (s *Server) removeHost(w http.ResponseWriter, r *http.Request) {
	host, err := store.RemoveHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	detail := ""
	if host.Transport == store.TransportAgent {
		detail = "agent credential revoked"
	}
	s.audit(r, "host.remove", host.Address, detail)
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	host, err := store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	var request startScanRequest
	if !readJSON(w, r, &request) {
		return
	}
	if len(request.Checks) == 0 {
		request.Checks = []string{checks.Packages}
	}
	selected, err := checks.Normalize(request.Checks)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if host.Transport == store.TransportAgent && !s.network {
		writeError(w, http.StatusConflict, errors.New("agent hosts are scanned when DeaconGuard serves on the network (deaconguard serve --listen 0.0.0.0:8443)"))
		return
	}
	scan, err := s.runner.start(host, selected)
	if errors.Is(err, errScanInProgress) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if host.Transport == store.TransportAgent {
		s.agents.wake(host.ID)
	}
	s.audit(r, "scan.start", host.Address, strings.Join(selected, ", "))
	writeJSON(w, http.StatusAccepted, scan)
}

type startScanRequest struct {
	Checks []string `json:"checks"`
}

func (s *Server) listPrompts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.runner.pending())
}

type respondRequest struct {
	Value  string `json:"value"`
	Cancel bool   `json:"cancel"`
}

// respond answers a scan that is waiting for the sudo password. The answer is
// handed to that scan only.
func (s *Server) respond(w http.ResponseWriter, r *http.Request) {
	var request respondRequest
	if !readJSON(w, r, &request) {
		return
	}
	err := s.runner.respond(r.PathValue("id"), []byte(request.Value), request.Cancel)
	if errors.Is(err, errNoPrompt) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type scanDetail struct {
	Scan   store.Scan     `json:"scan"`
	Report map[string]any `json:"report"`
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	scan, err := store.GetScan(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	detail := scanDetail{Scan: scan}
	if scan.Status == store.ScanSucceeded {
		report, err := store.GetReport(scan.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		detail.Report = report
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) deleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	record, _ := store.GetScan(id)
	err := store.DeleteScan(id)
	switch {
	case errors.Is(err, store.ErrScanInProgress):
		writeError(w, http.StatusConflict, err)
	case err != nil:
		writeError(w, http.StatusNotFound, err)
	default:
		s.runner.forget(id)
		action := "scan.delete"
		if record.Status == store.ScanQueued {
			action = "scan.cancel"
		}
		s.audit(r, action, record.Address, record.StartedAt)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (s *Server) listVulnerabilities(w http.ResponseWriter, r *http.Request) {
	vulnerabilities, err := store.Vulnerabilities()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, vulnerabilities)
}

func (s *Server) getVulnerability(w http.ResponseWriter, r *http.Request) {
	affected, err := store.VulnerabilityHosts(r.PathValue("cve"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, affected)
}

// serveUI serves the built web app, falling back to index.html so client-side
// routes such as /hosts/ID load directly.
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name != "" {
		if info, err := fs.Stat(s.ui, name); err == nil && !info.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, s.ui, name)
			return
		}
	}
	index, err := fs.ReadFile(s.ui, "index.html")
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "The DeaconGuard web UI was not built into this binary. Run `make ui build` and restart.\n")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(index)
}

func readJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
