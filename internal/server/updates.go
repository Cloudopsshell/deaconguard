package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/store"
	"deaconguard/internal/updates"
)

// How the update check paces itself: a first look shortly after the server
// starts, then once a day; a failure is tried again after an hour. Between
// looks it wakes hourly only to see whether one is due.
const (
	updateFirstDelay = time.Minute
	updateWake       = time.Hour
	updateRetry      = time.Hour
)

// upgradeNotes is where each release says what to do when upgrading to it.
const upgradeNotes = "https://docs.deaconguard.io/upgrade-notes/"

// updateChecker asks, once a day, which DeaconGuard release is the newest,
// so admins see when the server is behind. It only reads a public file.
type updateChecker struct {
	// url is asked; DEACONGUARD_UPDATE_URL names a mirror.
	url string
	// off is set by DEACONGUARD_UPDATE_CHECK=off: nothing is asked, whatever
	// Settings says.
	off bool
	// version is this server's.
	version string
	now     func() time.Time

	// one check at a time.
	checking sync.Mutex
	wake     chan struct{}
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func newUpdateChecker() *updateChecker {
	checker := &updateChecker{url: updates.StableURL, version: buildinfo.Version, now: time.Now, wake: make(chan struct{}, 1)}
	setting := strings.ToLower(strings.TrimSpace(os.Getenv("DEACONGUARD_UPDATE_CHECK")))
	checker.off = slices.Contains([]string{"off", "false", "0", "no"}, setting)
	if mirror := strings.TrimSpace(os.Getenv("DEACONGUARD_UPDATE_URL")); mirror != "" {
		if parsed, err := url.Parse(mirror); err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != "" {
			checker.url = mirror
		} else {
			log.Printf("WARNING DEACONGUARD_UPDATE_URL isn't an http or https address (%q); the update check is off", mirror)
			checker.off = true
		}
	}
	return checker
}

// runs reports whether this server ever asks: not when the environment
// turned the check off, nor a local build, which no release replaces.
func (c *updateChecker) runs() bool {
	return !c.off && updates.Comparable(c.version)
}

// checkDue asks for the newest release when the check is on and a day has
// passed since the last answer, or an hour since a failure; force asks now.
func (c *updateChecker) checkDue(ctx context.Context, force bool) {
	if !c.runs() {
		return
	}
	c.checking.Lock()
	defer c.checking.Unlock()
	check, err := store.GetUpdateCheck()
	if err != nil || !check.Enabled {
		return
	}
	now := c.now()
	wait := updates.Interval
	if check.Error != "" {
		wait = updateRetry
	}
	if !force && !check.CheckedAt.IsZero() && now.Sub(check.CheckedAt) < wait {
		return
	}
	latest, failure := updates.Latest(ctx, c.url)
	if ctx.Err() != nil {
		return
	}
	if err := store.RecordUpdateCheck(latest, failure, now); err != nil {
		log.Printf("WARNING The update check's result could not be saved: %v", err)
		return
	}
	if failure == nil && latest != check.Latest && updates.Newer(c.version, latest) {
		serverLog("", store.LogInfo, "DeaconGuard %s is available; this server runs %s. What to do when upgrading: %s", latest, c.version, upgradeNotes+latest)
	}
}

func (s *Server) startUpdateCheck() {
	checker := s.updates
	if !checker.runs() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	checker.cancel = cancel
	checker.wg.Add(1)
	go func() {
		defer checker.wg.Done()
		timer := time.NewTimer(updateFirstDelay)
		defer timer.Stop()
		for {
			force := false
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-checker.wake:
				force = true
			}
			checker.checkDue(ctx, force)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(updateWake)
		}
	}()
}

func (s *Server) stopUpdateCheck() {
	if s.updates.cancel != nil {
		s.updates.cancel()
		s.updates.wg.Wait()
	}
}

// updateResponse is what the dashboard shows about new releases.
type updateResponse struct {
	// Enabled is the Settings switch. Managed is set when the environment
	// turned the check off, so the switch does nothing.
	Enabled bool `json:"enabled"`
	Managed bool `json:"managed,omitempty"`
	// Current is this server's version; Release is false for a local build,
	// which is never compared.
	Current string `json:"current"`
	Release bool   `json:"release"`
	// Latest is the newest release last heard of, and Available whether it
	// is newer than this server; NotesURL is its upgrade notes.
	Latest    string     `json:"latest,omitempty"`
	Available bool       `json:"available"`
	NotesURL  string     `json:"notes_url,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Error is why the last check failed.
	Error string `json:"error,omitempty"`
}

func (s *Server) updateStatus() (updateResponse, error) {
	checker := s.updates
	response := updateResponse{Current: checker.version, Release: updates.Comparable(checker.version), Managed: checker.off}
	check, err := store.GetUpdateCheck()
	if err != nil {
		return response, err
	}
	response.Enabled = check.Enabled && !checker.off
	if !response.Enabled || !response.Release {
		return response, nil
	}
	response.Latest, response.Error = check.Latest, check.Error
	if !check.CheckedAt.IsZero() {
		response.CheckedAt = &check.CheckedAt
	}
	if updates.Newer(checker.version, check.Latest) {
		response.Available = true
		response.NotesURL = upgradeNotes + check.Latest
	}
	return response, nil
}

// getUpdate says whether a newer release is out: GET /api/update.
func (s *Server) getUpdate(w http.ResponseWriter, r *http.Request) {
	response, err := s.updateStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type updateSettingsRequest struct {
	Enabled *bool `json:"enabled"`
}

// setUpdateSettings turns the update check on or off: PUT
// /api/settings/updates. Turning it on asks straight away.
func (s *Server) setUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var request updateSettingsRequest
	if !readJSON(w, r, &request) {
		return
	}
	if request.Enabled == nil {
		writeError(w, http.StatusBadRequest, errors.New("enabled is required"))
		return
	}
	if s.updates.off && *request.Enabled {
		writeError(w, http.StatusConflict, errors.New("the update check is turned off in the server's environment (DEACONGUARD_UPDATE_CHECK); remove that to turn it on here"))
		return
	}
	if err := store.SetUpdateCheck(*request.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	detail := "check for new versions: off"
	if *request.Enabled {
		detail = "check for new versions: on"
		select {
		case s.updates.wake <- struct{}{}:
		default:
		}
	}
	s.audit(r, "settings.updates", "update check", detail)
	s.getUpdate(w, r)
}
