package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/iac"
	"deaconguard/internal/netscan"
	"deaconguard/internal/notify"
	"deaconguard/internal/store"
)

// Limits of a network target.
const (
	maxNetworkAddresses = 4096
	networkScanTimeout  = time.Hour
)

// networkIntervals are the choices for how often a target is scanned.
var networkIntervals = []int{0, 1, 6, 12, 24, 168}

// scanNetworkFunc runs one network scan; tests replace it.
type scanNetworkFunc func(ctx context.Context, target store.NetworkTarget) (netscan.Result, error)

func scanNetwork(ctx context.Context, target store.NetworkTarget) (netscan.Result, error) {
	ports, err := netscan.ParsePorts(target.Ports)
	if err != nil {
		return netscan.Result{}, err
	}
	targets, err := netscan.ParseTargets(ctx, target.Targets, maxNetworkAddresses)
	if err != nil {
		return netscan.Result{}, err
	}
	// Gentler than the command line's default: the server scans unattended.
	return netscan.Scan(ctx, targets, netscan.Options{Ports: ports, TLS: target.TLS, Concurrency: 32, Timeout: 2 * time.Second}), nil
}

// networkScanner runs queued network scans one at a time, and queues those
// of targets that are due.
type networkScanner struct {
	scan   scanNetworkFunc
	wake   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newNetworkScanner() *networkScanner {
	return &networkScanner{scan: scanNetwork, wake: make(chan struct{}, 1)}
}

func (s *Server) startNetworkScanner() {
	if err := store.InterruptNetworkScans(); err != nil {
		serverLog("", store.LogError, "Could not close network scans interrupted by a restart: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.netScans.cancel = cancel
	s.netScans.wg.Add(1)
	go func() {
		defer s.netScans.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			s.queueDueNetworkScans(time.Now())
			s.runQueuedNetworkScans(ctx)
			select {
			case <-ctx.Done():
				return
			case <-s.netScans.wake:
			case <-ticker.C:
			}
		}
	}()
}

func (s *Server) stopNetworkScanner() {
	if s.netScans.cancel != nil {
		s.netScans.cancel()
		s.netScans.wg.Wait()
	}
}

func (s *Server) wakeNetworkScanner() {
	select {
	case s.netScans.wake <- struct{}{}:
	default:
	}
}

func (s *Server) queueDueNetworkScans(now time.Time) {
	due, err := store.DueNetworkTargets(now)
	if err != nil {
		serverLog("", store.LogError, "Could not read the network targets: %v", err)
		return
	}
	for _, target := range due {
		if _, err := store.QueueNetworkScan(target.ID, "schedule"); err == nil {
			serverLog("", store.LogInfo, "Network scan of %q queued: every %d hours", target.Name, target.IntervalHours)
		}
	}
}

func (s *Server) runQueuedNetworkScans(ctx context.Context) {
	for ctx.Err() == nil {
		record, found, err := store.NextNetworkScan()
		if err != nil {
			serverLog("", store.LogError, "Could not read the queued network scans: %v", err)
			return
		}
		if !found {
			return
		}
		s.runNetworkScan(ctx, record)
	}
}

func (s *Server) runNetworkScan(ctx context.Context, record store.NetworkScan) {
	target, err := store.GetNetworkTarget(record.TargetID)
	if err != nil {
		store.FailNetworkScan(record.ID, err.Error())
		return
	}
	serverLog("", store.LogInfo, "Network scan of %q started by %s: %s", target.Name, record.StartedBy, strings.Join(target.Targets, ", "))
	ctx, cancel := context.WithTimeout(ctx, networkScanTimeout)
	defer cancel()
	result, err := s.netScans.scan(ctx, target)
	if err != nil {
		serverLog("", store.LogWarning, "Network scan of %q failed: %v", target.Name, err)
		store.FailNetworkScan(record.ID, err.Error())
		s.emit(notify.Message{Event: notify.EventScanFailed, Level: notify.LevelWarning, Title: fmt.Sprintf("Network %s: scan failed", target.Name),
			Lines: []string{err.Error()}, Link: link("/network/" + target.ID), Data: map[string]any{"target": target.Name}})
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		store.FailNetworkScan(record.ID, err.Error())
		return
	}
	record.Result, record.Hosts = encoded, len(result.Hosts)
	for _, host := range result.Hosts {
		record.OpenPorts += len(host.Services)
	}
	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			record.Severity.Critical++
		case "HIGH":
			record.Severity.High++
		case "MEDIUM":
			record.Severity.Medium++
		case "LOW":
			record.Severity.Low++
		}
	}
	if err := store.FinishNetworkScan(record); err != nil {
		serverLog("", store.LogError, "Could not save the network scan of %q: %v", target.Name, err)
		return
	}
	serverLog("", store.LogInfo, "Network scan of %q finished: %d hosts with %d open ports, %d findings", target.Name, record.Hosts, record.OpenPorts, len(result.Findings))
	s.newNetworkFindings(target, record.ID, result.Findings)
}

// networkFindings are a scan's critical and high findings by rule and title.
func networkFindings(findings []iac.Finding) map[string]iac.Finding {
	found := map[string]iac.Finding{}
	for _, f := range findings {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			found[f.Rule+"\x00"+f.Title] = f
		}
	}
	return found
}

// newNetworkFindings notifies about critical and high findings the
// target's previous succeeded scan didn't have, such as a newly exposed
// database or an expiring certificate.
func (s *Server) newNetworkFindings(target store.NetworkTarget, scanID string, findings []iac.Finding) {
	current := networkFindings(findings)
	previous := map[string]iac.Finding{}
	if scans, err := store.NetworkScans(target.ID); err == nil {
		for _, earlier := range scans {
			if earlier.ID == scanID || earlier.Status != store.ScanSucceeded {
				continue
			}
			if full, err := store.GetNetworkScan(earlier.ID); err == nil {
				var result netscan.Result
				if json.Unmarshal(full.Result, &result) == nil {
					previous = networkFindings(result.Findings)
				}
			}
			break
		}
	}
	var added []iac.Finding
	critical := false
	for key, f := range current {
		if _, seen := previous[key]; !seen {
			added = append(added, f)
			critical = critical || f.Severity == "CRITICAL"
		}
	}
	if len(added) == 0 {
		return
	}
	sort.Slice(added, func(i, j int) bool {
		if added[i].Severity != added[j].Severity {
			return added[i].Severity == "CRITICAL"
		}
		return added[i].Title < added[j].Title
	})
	level := notify.LevelWarning
	if critical {
		level = notify.LevelCritical
	}
	var lines, rules []string
	for index, f := range added {
		rules = append(rules, f.Rule)
		if index < 10 {
			lines = append(lines, f.Severity+": "+f.Title)
		}
	}
	if len(added) > 10 {
		lines = append(lines, fmt.Sprintf("… and %d more", len(added)-10))
	}
	s.emit(notify.Message{Event: notify.EventExposure, Level: level,
		Title: fmt.Sprintf("Network %s: %s", target.Name, plural(len(added), "new critical or high finding", "new critical or high findings")),
		Lines: lines, Link: link("/network/" + target.ID), Data: map[string]any{"target": target.Name, "rules": rules}})
}

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

type networkTargetRequest struct {
	Name          string   `json:"name"`
	Targets       []string `json:"targets"`
	Ports         string   `json:"ports"`
	TLS           *bool    `json:"tls"`
	IntervalHours int      `json:"interval_hours"`
}

// apply checks request and copies it into target. Names aren't resolved
// here; a scan resolves them.
func (request networkTargetRequest) apply(target *store.NetworkTarget) error {
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > 80 {
		return errors.New("give the target a name of up to 80 characters")
	}
	var targets []string
	addresses := 0
	for _, item := range request.Targets {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			bits := prefix.Addr().BitLen() - prefix.Bits()
			if bits > 12 {
				return fmt.Errorf("%s is larger than a /20 (4096 addresses): split it into several targets", item)
			}
			addresses += 1 << bits
		} else if _, err := netip.ParseAddr(item); err == nil {
			addresses++
		} else if hostnamePattern.MatchString(item) && len(item) <= 253 {
			addresses++
		} else {
			return fmt.Errorf("%q is not an address, a range (10.0.0.0/24) or a host name", item)
		}
		if !slices.Contains(targets, item) {
			targets = append(targets, item)
		}
	}
	if len(targets) == 0 {
		return errors.New("give at least one address, range or host name")
	}
	if addresses > maxNetworkAddresses {
		return fmt.Errorf("the target covers %d addresses; at most %d", addresses, maxNetworkAddresses)
	}
	ports := strings.TrimSpace(request.Ports)
	if _, err := netscan.ParsePorts(ports); err != nil {
		return err
	}
	if !slices.Contains(networkIntervals, request.IntervalHours) {
		return errors.New("scan it on request (0), or every 1, 6, 12, 24 or 168 hours")
	}
	target.Name, target.Targets, target.Ports, target.IntervalHours = name, targets, ports, request.IntervalHours
	target.TLS = request.TLS == nil || *request.TLS
	return nil
}

func (s *Server) listNetworkTargets(w http.ResponseWriter, r *http.Request) {
	list, err := store.NetworkTargets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createNetworkTarget(w http.ResponseWriter, r *http.Request) {
	var request networkTargetRequest
	if !readJSON(w, r, &request) {
		return
	}
	target := store.NetworkTarget{CreatedBy: s.actor(r)}
	if err := request.apply(&target); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := store.SaveNetworkTarget(target)
	if errors.Is(err, store.ErrNetworkTargetExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "network.create", saved.Name, strings.Join(saved.Targets, ", "))
	if _, err := store.QueueNetworkScan(saved.ID, s.actor(r)); err == nil {
		s.wakeNetworkScanner()
	}
	saved, _ = store.GetNetworkTarget(saved.ID)
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) updateNetworkTarget(w http.ResponseWriter, r *http.Request) {
	target, err := store.GetNetworkTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	var request networkTargetRequest
	if !readJSON(w, r, &request) {
		return
	}
	if err := request.apply(&target); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := store.SaveNetworkTarget(target)
	if errors.Is(err, store.ErrNetworkTargetExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "network.update", saved.Name, strings.Join(saved.Targets, ", "))
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteNetworkTarget(w http.ResponseWriter, r *http.Request) {
	target, err := store.DeleteNetworkTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "network.delete", target.Name, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) networkTargetDetail(w http.ResponseWriter, r *http.Request) {
	target, err := store.GetNetworkTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	scans, err := store.NetworkScans(target.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": target, "scans": scans})
}

func (s *Server) scanNetworkTarget(w http.ResponseWriter, r *http.Request) {
	target, err := store.GetNetworkTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	record, err := store.QueueNetworkScan(target.ID, s.actor(r))
	switch {
	case errors.Is(err, store.ErrNetworkScanInProgress):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "network.scan", target.Name, strings.Join(target.Targets, ", "))
	s.wakeNetworkScanner()
	writeJSON(w, http.StatusAccepted, record)
}

func (s *Server) networkScan(w http.ResponseWriter, r *http.Request) {
	record, err := store.GetNetworkScan(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}
