package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/schedule"
	"deaconguard/internal/store"
)

// scheduleTick is how often the server looks for scheduled scans that are due.
const scheduleTick = 30 * time.Second

// scheduler starts scheduled scans when they are due.
type scheduler struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex // one pass at a time
}

func (s *Server) startScheduler() {
	ctx, cancel := context.WithCancel(context.Background())
	s.scheduler.cancel = cancel
	s.scheduler.wg.Add(1)
	go func() {
		defer s.scheduler.wg.Done()
		// The first pass runs scans missed while the server was stopped.
		s.runDueSchedules(time.Now())
		ticker := time.NewTicker(scheduleTick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.runDueSchedules(now)
			}
		}
	}()
}

func (s *Server) stopScheduler() {
	if s.scheduler.cancel != nil {
		s.scheduler.cancel()
		s.scheduler.wg.Wait()
	}
}

// runDueSchedules starts the scans of every schedule due at now, and sets
// each one's next run. A run missed while the server was stopped happens
// once, now.
func (s *Server) runDueSchedules(now time.Time) {
	s.scheduler.mu.Lock()
	defer s.scheduler.mu.Unlock()
	due, err := store.DueSchedules(now)
	if err != nil {
		serverLog("", store.LogError, "Could not read the scan schedules: %v", err)
		return
	}
	for _, item := range due {
		next := ""
		if at, err := when(item).Next(now); err == nil {
			next = at.Format(time.RFC3339)
		}
		// Record the run first, so a failure below never repeats it every tick.
		if err := store.ScheduleRan(item.ID, now, next); err != nil {
			serverLog("", store.LogError, "Could not record the run of schedule %q: %v", item.Name, err)
			continue
		}
		s.runSchedule(item)
	}
}

// runSchedule starts a scan of each of the schedule's hosts.
func (s *Server) runSchedule(item store.Schedule) (started, skipped int) {
	hosts, err := store.ListHosts()
	if err != nil {
		serverLog("", store.LogError, "Schedule %q could not list the hosts: %v", item.Name, err)
		return 0, 0
	}
	actor := "schedule: " + item.Name
	for _, host := range hosts {
		if !item.Covers(host.ID) {
			continue
		}
		reason := ""
		switch {
		case host.Transport == store.TransportAgent && !s.network:
			reason = "agent hosts are scanned only when DeaconGuard serves on the network"
		default:
			if err := checkAgentVersion(host, item.Checks); err != nil {
				reason = err.Error()
			} else if _, err := s.runner.start(host, item.Checks, true); errors.Is(err, errScanInProgress) {
				reason = "a scan of it is already queued or running"
			} else if err != nil {
				reason = err.Error()
			}
		}
		if reason != "" {
			skipped++
			serverLog(host.ID, store.LogWarning, "Schedule %q skipped %s: %s", item.Name, host.Address, reason)
			continue
		}
		started++
		if host.Transport == store.TransportAgent {
			s.agents.wake(host.ID)
		}
		store.Audit(actor, "scan.start", host.Address, strings.Join(item.Checks, ", "), "")
		serverLog(host.ID, store.LogInfo, "Scan of %s started by schedule %q: %s", host.Address, item.Name, strings.Join(item.Checks, ", "))
	}
	if started == 0 && skipped == 0 {
		serverLog("", store.LogWarning, "Schedule %q ran, but no host matches it", item.Name)
	}
	return started, skipped
}

func when(item store.Schedule) schedule.When {
	return schedule.When{Days: item.Days, Time: item.Time, Timezone: item.Timezone}
}

// scheduleView is a schedule as the dashboard shows it.
type scheduleView struct {
	store.Schedule
	Description string `json:"description"`
}

func viewOf(item store.Schedule) scheduleView {
	return scheduleView{Schedule: item, Description: when(item).Describe()}
}

type scheduleRequest struct {
	Name     string   `json:"name"`
	Enabled  *bool    `json:"enabled"`
	Checks   []string `json:"checks"`
	AllHosts bool     `json:"all_hosts"`
	HostIDs  []string `json:"host_ids"`
	Days     []int    `json:"days"`
	Time     string   `json:"time"`
	Timezone string   `json:"timezone"`
}

// apply checks request and copies it into item, setting the next run.
func (request scheduleRequest) apply(item *store.Schedule, now time.Time) error {
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > 80 {
		return errors.New("give the schedule a name of up to 80 characters")
	}
	selected, err := checks.Normalize(request.Checks)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return errors.New("choose at least one check")
	}
	hostIDs := make([]string, 0, len(request.HostIDs))
	if !request.AllHosts {
		if len(request.HostIDs) == 0 {
			return errors.New("choose at least one host, or all hosts")
		}
		seen := map[string]bool{}
		for _, id := range request.HostIDs {
			if seen[id] {
				continue
			}
			if _, err := store.GetHost(id); err != nil {
				return fmt.Errorf("unknown host ID: %s", id)
			}
			seen[id] = true
			hostIDs = append(hostIDs, id)
		}
	}
	timing := schedule.When{Days: request.Days, Time: request.Time, Timezone: request.Timezone}
	next, err := timing.Next(now)
	if err != nil {
		return err
	}
	item.Name, item.Checks, item.AllHosts, item.HostIDs = name, selected, request.AllHosts, hostIDs
	item.Days, item.Time, item.Timezone = request.Days, request.Time, request.Timezone
	if request.Enabled != nil {
		item.Enabled = *request.Enabled
	}
	item.NextRunAt = ""
	if item.Enabled {
		item.NextRunAt = next.Format(time.RFC3339)
	}
	return nil
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := store.Schedules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]scheduleView, 0, len(items))
	for _, item := range items {
		views = append(views, viewOf(item))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	var request scheduleRequest
	if !readJSON(w, r, &request) {
		return
	}
	item := store.Schedule{Enabled: true, CreatedBy: s.actor(r)}
	if err := request.apply(&item, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := store.SaveSchedule(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "schedule.create", saved.Name, when(saved).Describe())
	writeJSON(w, http.StatusCreated, viewOf(saved))
}

func (s *Server) updateSchedule(w http.ResponseWriter, r *http.Request) {
	item, err := store.GetSchedule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	var request scheduleRequest
	if !readJSON(w, r, &request) {
		return
	}
	if err := request.apply(&item, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := store.SaveSchedule(item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	state := "on"
	if !saved.Enabled {
		state = "off"
	}
	s.audit(r, "schedule.update", saved.Name, when(saved).Describe()+", "+state)
	writeJSON(w, http.StatusOK, viewOf(saved))
}

func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	item, err := store.DeleteSchedule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "schedule.delete", item.Name, "")
	w.WriteHeader(http.StatusNoContent)
}

// runScheduleNow starts the schedule's scans at once; its next run stays.
func (s *Server) runScheduleNow(w http.ResponseWriter, r *http.Request) {
	item, err := store.GetSchedule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "schedule.run", item.Name, "")
	started, skipped := s.runSchedule(item)
	writeJSON(w, http.StatusAccepted, map[string]int{"started": started, "skipped": skipped})
}
