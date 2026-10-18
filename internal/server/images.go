package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/containers"
	"deaconguard/internal/images"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

// imageScanTimeout bounds one image scan: a large image on a slow registry.
const imageScanTimeout = 30 * time.Minute

// readImageFunc reads an image from its registry; tests replace it.
type readImageFunc func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error)

func readImage(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
	return images.Read(ctx, client, ref, platform, nil)
}

// imageScanner runs queued image scans one at a time, on the server: it reads
// each image from its registry, never running it.
type imageScanner struct {
	read   readImageFunc
	wake   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newImageScanner() *imageScanner {
	return &imageScanner{read: readImage, wake: make(chan struct{}, 1)}
}

func (s *Server) startImageScanner() {
	if err := store.InterruptImageScans(); err != nil {
		serverLog("", store.LogError, "Could not close image scans interrupted by a restart: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.images.cancel = cancel
	s.images.wg.Add(1)
	go func() {
		defer s.images.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			s.runQueuedImageScans(ctx)
			select {
			case <-ctx.Done():
				return
			case <-s.images.wake:
			case <-ticker.C:
			}
		}
	}()
}

func (s *Server) stopImageScanner() {
	if s.images.cancel != nil {
		s.images.cancel()
		s.images.wg.Wait()
	}
}

// wakeImageScanner makes the scanner look for queued scans now.
func (s *Server) wakeImageScanner() {
	select {
	case s.images.wake <- struct{}{}:
	default:
	}
}

func (s *Server) runQueuedImageScans(ctx context.Context) {
	for ctx.Err() == nil {
		record, found, err := store.NextImageScan()
		if err != nil {
			serverLog("", store.LogError, "Could not read the queued image scans: %v", err)
			return
		}
		if !found {
			return
		}
		s.runImageScan(ctx, record)
	}
}

// registryCredentials gives the image reader the saved login for a registry.
func registryCredentials(registry string) (images.Credentials, bool) {
	login, found, err := store.RegistryLoginFor(registry)
	if err != nil || !found {
		return images.Credentials{}, false
	}
	return images.Credentials{Username: login.Username, Password: login.Secret}, true
}

func (s *Server) runImageScan(ctx context.Context, record store.ImageScan) {
	image, err := store.GetImage(record.ImageID)
	if err != nil {
		store.FailImageScan(record.ID, err.Error())
		return
	}
	fail := func(message string) {
		serverLog("", store.LogWarning, "Scan of image %s (%s) failed: %s", image.Reference, image.Platform, message)
		if err := store.FailImageScan(record.ID, message); err != nil {
			serverLog("", store.LogError, "Could not save the failed scan of image %s: %v", image.Reference, err)
		}
	}
	ref, err := images.ParseReference(image.Reference)
	if err != nil {
		fail(err.Error())
		return
	}
	serverLog("", store.LogInfo, "Scan of image %s (%s) started by %s", image.Reference, image.Platform, record.StartedBy)
	ctx, cancel := context.WithTimeout(ctx, imageScanTimeout)
	defer cancel()
	inventory, resolved, err := s.images.read(ctx, images.NewClient(registryCredentials), ref, image.Platform)
	if err != nil {
		fail(err.Error())
		return
	}
	result := scan.EvaluateImage(inventory)
	encoded, err := json.Marshal(result)
	if err != nil {
		fail(err.Error())
		return
	}
	record.Digest, record.OS, record.Result = resolved.Digest, result.OS, encoded
	record.Severity = store.SeverityCounts{
		Critical: result.Severity["CRITICAL"], High: result.Severity["HIGH"], Medium: result.Severity["MEDIUM"],
		Low: result.Severity["LOW"], Unknown: result.Severity["UNKNOWN"],
	}
	record.Exploited, record.Fixable = result.Exploited, result.Fixable
	if err := store.FinishImageScan(record); err != nil {
		serverLog("", store.LogError, "Could not save the scan of image %s: %v", image.Reference, err)
		return
	}
	serverLog("", store.LogInfo, "Scan of image %s (%s) finished: %d critical, %d high, %d known to be exploited",
		image.Reference, image.Platform, record.Severity.Critical, record.Severity.High, record.Exploited)
}

func (s *Server) listImages(w http.ResponseWriter, r *http.Request) {
	list, err := store.Images()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type imageRequest struct {
	Reference string `json:"reference"`
	Platform  string `json:"platform"`
}

// addImage adds an image to check and queues its first scan.
func (s *Server) addImage(w http.ResponseWriter, r *http.Request) {
	var request imageRequest
	if !readJSON(w, r, &request) {
		return
	}
	ref, err := images.ParseReference(request.Reference)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	platform := strings.TrimSpace(request.Platform)
	if platform == "" {
		platform = "linux/amd64"
	}
	if !slices.Contains(images.Platforms, platform) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("the platform is one of %s", strings.Join(images.Platforms, ", ")))
		return
	}
	image, err := store.AddImage(ref.String(), platform, s.actor(r))
	if errors.Is(err, store.ErrImageExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "image.add", image.Reference, image.Platform)
	if _, err := store.QueueImageScan(image.ID, s.actor(r)); err == nil {
		s.wakeImageScanner()
	}
	image, _ = store.GetImage(image.ID)
	writeJSON(w, http.StatusCreated, image)
}

func (s *Server) imageDetail(w http.ResponseWriter, r *http.Request) {
	image, err := store.GetImage(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	scans, err := store.ImageScans(image.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"image": image, "scans": scans})
}

func (s *Server) deleteImage(w http.ResponseWriter, r *http.Request) {
	image, err := store.DeleteImage(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "image.delete", image.Reference, image.Platform)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scanImage(w http.ResponseWriter, r *http.Request) {
	image, err := store.GetImage(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	record, err := store.QueueImageScan(image.ID, s.actor(r))
	switch {
	case errors.Is(err, store.ErrImageScanInProgress):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "image.scan", image.Reference, image.Platform)
	s.wakeImageScanner()
	writeJSON(w, http.StatusAccepted, record)
}

func (s *Server) imageScan(w http.ResponseWriter, r *http.Request) {
	record, err := store.GetImageScan(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) listRegistryLogins(w http.ResponseWriter, r *http.Request) {
	logins, err := store.RegistryLogins()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, logins)
}

type registryLoginRequest struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	// Secret is a password or access token; empty keeps the saved one.
	Secret string `json:"secret"`
}

func (request registryLoginRequest) apply(login *store.RegistryLogin) error {
	host, err := images.RegistryHost(request.Registry)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(request.Username)
	if username == "" || len(username) > 256 {
		return errors.New("give the username, up to 256 characters")
	}
	if len(request.Secret) > 8192 {
		return errors.New("the password or token is longer than 8192 characters")
	}
	if login.ID == "" && request.Secret == "" {
		return errors.New("give the password or access token")
	}
	login.Registry, login.Username, login.Secret = host, username, request.Secret
	return nil
}

func (s *Server) createRegistryLogin(w http.ResponseWriter, r *http.Request) {
	var request registryLoginRequest
	if !readJSON(w, r, &request) {
		return
	}
	login := store.RegistryLogin{CreatedBy: s.actor(r)}
	if err := request.apply(&login); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.saveRegistryLogin(w, r, login, "registry_login.create", http.StatusCreated)
}

func (s *Server) updateRegistryLogin(w http.ResponseWriter, r *http.Request) {
	login, err := store.GetRegistryLogin(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	var request registryLoginRequest
	if !readJSON(w, r, &request) {
		return
	}
	if err := request.apply(&login); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.saveRegistryLogin(w, r, login, "registry_login.update", http.StatusOK)
}

func (s *Server) saveRegistryLogin(w http.ResponseWriter, r *http.Request, login store.RegistryLogin, action string, status int) {
	saved, err := store.SaveRegistryLogin(login)
	switch {
	case errors.Is(err, store.ErrRegistryLoginExists):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, action, saved.Registry, "user "+saved.Username)
	writeJSON(w, status, saved)
}

func (s *Server) deleteRegistryLogin(w http.ResponseWriter, r *http.Request) {
	login, err := store.DeleteRegistryLogin(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "registry_login.delete", login.Registry, "")
	w.WriteHeader(http.StatusNoContent)
}
