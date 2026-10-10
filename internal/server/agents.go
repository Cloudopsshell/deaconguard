package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/buildinfo"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
	"deaconguard/internal/target"
)

const (
	// queuedScanTimeout fails a scan its agent has not picked up by then.
	queuedScanTimeout = time.Hour
	// agentScanTimeout fails a running agent scan that has sent nothing for that long.
	agentScanTimeout = 20 * time.Minute
	// maxAgentEvents bounds one events request.
	maxAgentEvents = 500
)

// agentHub hands queued scans to agents and collects their progress and results.
type agentHub struct {
	runner *runner
	mu     sync.Mutex
	// wakers wake an agent's waiting job request when a scan is queued for it.
	wakers map[string]chan struct{}
	// active holds agent scans this process handed out and has not finished.
	active map[string]*agentScan
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type agentScan struct {
	host         store.Host
	log          *eventLog
	started      time.Time
	lastActivity time.Time
	finishing    bool
}

func newAgentHub(runner *runner) *agentHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &agentHub{runner: runner, wakers: make(map[string]chan struct{}), active: make(map[string]*agentScan), ctx: ctx, cancel: cancel}
}

// start runs the janitor that fails scans agents never pick up or finish.
func (h *agentHub) start() {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-ticker.C:
				h.expire()
			}
		}
	}()
}

func (h *agentHub) stop() {
	h.cancel()
	h.wg.Wait()
}

func (h *agentHub) expire() {
	expired, _ := store.ExpireQueuedScans(time.Now().Add(-queuedScanTimeout),
		fmt.Sprintf("the agent did not pick up the scan within %s; check that it is running", queuedScanTimeout))
	for _, id := range expired {
		if log := h.runner.logFor(id); log != nil {
			h.runner.publishFailure(id, log, "the agent did not pick up the scan")
		}
	}
	h.mu.Lock()
	var stale []string
	for id, active := range h.active {
		if !active.finishing && time.Since(active.lastActivity) > agentScanTimeout {
			stale = append(stale, id)
		}
	}
	h.mu.Unlock()
	for _, id := range stale {
		h.complete(id, nil, nil, fmt.Errorf("the agent stopped reporting for %s; it may have been restarted or lost its connection", agentScanTimeout))
	}
}

// wake tells hostID's waiting job request that a scan was queued.
func (h *agentHub) wake(hostID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if waker, ok := h.wakers[hostID]; ok {
		close(waker)
		delete(h.wakers, hostID)
	}
}

func (h *agentHub) waiter(hostID string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	waker, ok := h.wakers[hostID]
	if !ok {
		waker = make(chan struct{})
		h.wakers[hostID] = waker
	}
	return waker
}

type agentContextKey struct{}

// authenticated admits requests carrying an enrolled agent's credential.
func (h *agentHub) authenticated(next func(http.ResponseWriter, *http.Request, store.Host)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		credential, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		hostID, secret, split := strings.Cut(credential, ".")
		if !found || !split {
			writeError(w, http.StatusUnauthorized, errors.New("agent credential required"))
			return
		}
		host, err := store.AuthenticateAgent(hostID, secret, limitText(r.Header.Get(agentapi.HeaderVersion), 64), remoteIP(r))
		if errors.Is(err, store.ErrUnknownAgent) {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if r.Method == http.MethodPost {
			mediaType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
			if mediaType != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, errors.New("requests must use Content-Type: application/json"))
				return
			}
		}
		next(w, r, host)
	}
}

func (h *agentHub) enroll(limiter *failureLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remote := remoteIP(r)
		if limiter.blocked("enroll", remote) {
			writeError(w, http.StatusTooManyRequests, errors.New("too many failed enrollment attempts; try again later"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		var request agentapi.EnrollRequest
		if !readJSON(w, r, &request) {
			return
		}
		if !store.ValidHostname(request.Hostname) {
			writeError(w, http.StatusBadRequest, errors.New("the agent reported an invalid hostname"))
			return
		}
		host, credential, err := store.EnrollAgent(request.Secret, store.AgentEnrollment{
			Hostname: request.Hostname, Username: limitText(request.Username, 64), Version: limitText(request.Version, 64),
			OS: limitText(request.OS, 128), Remote: remote,
		})
		if errors.Is(err, store.ErrInvalidEnrollmentToken) {
			limiter.fail("enroll", remote)
			store.Audit("agent", "agent.enroll_failed", request.Hostname, err.Error(), remote)
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		store.Audit("agent", "agent.enroll", host.Address, fmt.Sprintf("%s, DeaconGuard %s", request.OS, request.Version), remote)
		writeJSON(w, http.StatusCreated, agentapi.EnrollResponse{HostID: host.ID, Credential: credential})
	}
}

// job hands the agent its next queued scan, waiting up to JobWait for one.
func (h *agentHub) job(w http.ResponseWriter, r *http.Request, host store.Host) {
	if hostname := r.Header.Get(agentapi.HeaderHostname); store.ValidHostname(hostname) {
		store.UpdateAgentHost(host.ID, hostname, limitText(r.Header.Get(agentapi.HeaderUsername), 64), limitText(r.Header.Get(agentapi.HeaderOS), 128))
		host.Address = hostname
	}
	deadline := time.NewTimer(agentapi.JobWait)
	defer deadline.Stop()
	for {
		waker := h.waiter(host.ID)
		record, found, err := store.ClaimQueuedScan(host.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if found {
			h.begin(host, record)
			writeJSON(w, http.StatusOK, agentapi.Job{ScanID: record.ID, Checks: record.Checks, AllowSudo: host.AllowSudo})
			return
		}
		// Scans queued by the CLI do not wake the waiter, so look again every few seconds.
		select {
		case <-waker:
		case <-time.After(3 * time.Second):
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		case <-h.ctx.Done():
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
}

func (h *agentHub) begin(host store.Host, record store.Scan) {
	log := h.runner.attach(host, record)
	log.add(scan.Event{Kind: "success", Phase: scan.PhaseConnect, Message: fmt.Sprintf("The agent on %s picked up the scan", host.Address)})
	started, err := time.Parse(time.RFC3339, record.StartedAt)
	if err != nil {
		started = time.Now()
	}
	h.mu.Lock()
	h.active[record.ID] = &agentScan{host: host, log: log, started: started, lastActivity: time.Now()}
	h.mu.Unlock()
}

// activeScan returns the agent scan scanID if host is running it.
func (h *agentHub) activeScan(scanID string, host store.Host) (*agentScan, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	active, ok := h.active[scanID]
	if !ok || active.host.ID != host.ID || active.finishing {
		return nil, false
	}
	active.lastActivity = time.Now()
	return active, true
}

var agentEventKinds = map[string]bool{
	"phase": true, "command": true, "result": true, "info": true, "success": true, "warning": true, "error": true, "finding": true,
}

func (h *agentHub) events(w http.ResponseWriter, r *http.Request, host store.Host) {
	active, ok := h.activeScan(r.PathValue("id"), host)
	if !ok {
		writeError(w, http.StatusConflict, errors.New("this agent is not running that scan"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var batch agentapi.Events
	if !readJSON(w, r, &batch) {
		return
	}
	if len(batch.Events) > maxAgentEvents {
		batch.Events = batch.Events[:maxAgentEvents]
	}
	for _, event := range batch.Events {
		if !agentEventKinds[event.Kind] {
			continue
		}
		active.log.add(scan.Event{
			Kind: event.Kind, Phase: limitText(event.Phase, 32), Message: limitText(event.Message, 400), Sudo: event.Sudo,
			Status: limitText(event.Status, 16), Severity: limitText(event.Severity, 16),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// agentReportKeys are the report fields an agent may set; package results are
// always evaluated by the server.
var agentReportKeys = []string{"os", "scanned_at", "checks_run", "check_results", "deaconguard_version"}

func (h *agentHub) result(w http.ResponseWriter, r *http.Request, host store.Host) {
	scanID := r.PathValue("id")
	if _, ok := h.activeScan(scanID, host); !ok {
		writeError(w, http.StatusConflict, errors.New("this agent is not running that scan"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, agentapi.MaxResultBytes)
	var result agentapi.Result
	if !readJSON(w, r, &result) {
		return
	}
	var failure error
	if result.Error != "" {
		failure = errors.New(limitText(result.Error, 1000))
	} else if result.Report == nil {
		failure = errors.New("the agent sent no report")
	}
	report := make(map[string]any)
	for _, key := range agentReportKeys {
		if value, ok := result.Report[key]; ok {
			report[key] = value
		}
	}
	report["host_id"], report["address"] = host.ID, host.Address
	w.WriteHeader(http.StatusAccepted)
	h.runner.wg.Add(1)
	go func() {
		defer h.runner.wg.Done()
		h.complete(scanID, report, result.Inventory, failure)
	}()
}

// complete evaluates an agent's packages, if it sent them, and finishes the scan.
func (h *agentHub) complete(scanID string, report map[string]any, inventory *target.Inventory, failure error) {
	h.mu.Lock()
	active, ok := h.active[scanID]
	if !ok || active.finishing {
		h.mu.Unlock()
		return
	}
	active.finishing = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.active, scanID)
		h.mu.Unlock()
	}()
	if failure == nil && inventory != nil {
		failure = scan.EvaluateInventory(report, *inventory, active.log.add)
	}
	h.runner.finish(active.host, scanID, active.log, report, failure, active.started)
}

func limitText(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	if len(value) > limit {
		value = value[:limit]
	}
	return strings.ToValidUTF8(value, "")
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// enrollmentTokenResponse is returned once, when a token is created: Token is
// the only copy of the secret.
type enrollmentTokenResponse struct {
	store.EnrollmentToken
	Token string `json:"token"`
	// Command installs the agent and enrolls it with Token, in one line.
	Command string `json:"command"`
}

type createTokenRequest struct {
	ServerURL string `json:"server_url"`
}

func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if !s.network {
		writeError(w, http.StatusConflict, errNeedsNetworkMode)
		return
	}
	var request createTokenRequest
	if !readJSON(w, r, &request) {
		return
	}
	request.ServerURL = strings.TrimSuffix(strings.TrimSpace(request.ServerURL), "/")
	if err := agentapi.ValidateServerURL(request.ServerURL); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	token, secret, err := store.CreateEnrollmentToken(request.ServerURL, s.actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	encoded := agentapi.Token{ServerURL: request.ServerURL, Pin: s.pin, Secret: secret}.Encode()
	s.audit(r, "token.create", token.ID[:8], "for "+request.ServerURL+", expires "+token.ExpiresAt)
	writeJSON(w, http.StatusCreated, enrollmentTokenResponse{EnrollmentToken: token, Token: encoded, Command: buildinfo.AgentInstallCommand(encoded)})
}

func (s *Server) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := store.ListEnrollmentTokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	token, err := store.RevokeEnrollmentToken(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "token.revoke", token.ID[:8], "")
	writeJSON(w, http.StatusOK, token)
}

var errNeedsNetworkMode = errors.New("agents enroll with a DeaconGuard server on the network: run deaconguard serve --listen 0.0.0.0:8443")
