package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/containers"
	"deaconguard/internal/images"
	"deaconguard/internal/notify"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

// imageScanTimeout bounds one image scan: a large image on a slow registry.
const imageScanTimeout = 30 * time.Minute

// A watched image's tag is checked for a new build every watchInterval, and
// the image is scanned again at least every rescanInterval, for advisories
// published since.
const (
	watchInterval  = 15 * time.Minute
	rescanInterval = 24 * time.Hour
)

// readImageFunc reads an image from its registry; tests replace it.
type readImageFunc func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error)

func readImage(ctx context.Context, client *images.Client, ref images.Reference, platform string) (containers.Inventory, images.Resolved, error) {
	return images.Read(ctx, client, ref, platform, nil)
}

// tagDigestFunc asks a registry what a tag points to; tests replace it.
type tagDigestFunc func(ctx context.Context, client *images.Client, ref images.Reference) (string, error)

func tagDigest(ctx context.Context, client *images.Client, ref images.Reference) (string, error) {
	return client.TagDigest(ctx, ref)
}

// imageScanner runs queued image scans one at a time, on the server: it reads
// each image from its registry, never running it. It also checks watched
// images for new builds.
type imageScanner struct {
	read      readImageFunc
	tagDigest tagDigestFunc
	// checkLogin logs in to a registry with a saved login; tests replace it.
	checkLogin func(ctx context.Context, client *images.Client, registry string) error
	wake       chan struct{}
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	// http and ecrEndpoint reach the ECR API; tests point them elsewhere.
	http        *http.Client
	ecrEndpoint string
	mu          sync.Mutex
	ecrTokens   map[string]ecrToken
}

// ecrToken is an ECR registry password, for the saved login it came from.
type ecrToken struct {
	credentials images.Credentials
	login       string // the saved login it came from: its ID and key
	until       time.Time
}

func newImageScanner() *imageScanner {
	return &imageScanner{read: readImage, tagDigest: tagDigest, wake: make(chan struct{}, 1),
		checkLogin: func(ctx context.Context, client *images.Client, registry string) error {
			return client.CheckLogin(ctx, registry)
		},
		http: &http.Client{Timeout: 30 * time.Second}, ecrTokens: map[string]ecrToken{}}
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
			s.checkWatchedImages(ctx, time.Now())
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

// registryClient makes a registry client with the saved login for the
// image's registry. An Amazon ECR login is exchanged for its 12-hour
// password first, so a wrong AWS key fails here with AWS's reason.
func (s *Server) registryClient(ctx context.Context, registry string) (*images.Client, error) {
	login, found, err := store.RegistryLoginFor(registry)
	if err != nil {
		return nil, err
	}
	credentials := images.Credentials{Username: login.Username, Password: login.Secret}
	if found && login.Kind == store.LoginECR {
		if credentials, err = s.ecrCredentials(ctx, login); err != nil {
			return nil, err
		}
	}
	return images.NewClient(func(host string) (images.Credentials, bool) {
		return credentials, found && host == registry
	}), nil
}

func (s *Server) ecrCredentials(ctx context.Context, login store.RegistryLogin) (images.Credentials, error) {
	// A changed key gets a new token; this stays in memory only.
	version := login.ID + "\x00" + login.Username + "\x00" + login.Secret
	s.images.mu.Lock()
	cached, ok := s.images.ecrTokens[login.Registry]
	s.images.mu.Unlock()
	// Renew an hour early, so a scan never starts with a token about to expire.
	if ok && cached.login == version && time.Now().Add(time.Hour).Before(cached.until) {
		return cached.credentials, nil
	}
	credentials, until, err := images.ECRToken(ctx, s.images.http, login.Registry, s.images.ecrEndpoint, login.Username, login.Secret, time.Now())
	if err != nil {
		return images.Credentials{}, err
	}
	s.images.mu.Lock()
	s.images.ecrTokens[login.Registry] = ecrToken{credentials: credentials, login: version, until: until}
	s.images.mu.Unlock()
	return credentials, nil
}

// checkWatchedImages asks the registry of each watched image that is due
// what its tag points to, and queues a scan when that changed, or when the
// image was last scanned a day ago.
func (s *Server) checkWatchedImages(ctx context.Context, now time.Time) {
	list, err := store.Images()
	if err != nil {
		serverLog("", store.LogError, "Could not read the watched images: %v", err)
		return
	}
	queued := false
	for _, image := range list {
		if ctx.Err() != nil {
			return
		}
		if !image.Watch || scanning(image) {
			continue
		}
		if checked, err := time.Parse(time.RFC3339, image.CheckedAt); err == nil && now.Sub(checked) < watchInterval {
			continue
		}
		digest, failure := s.watchCheck(ctx, image)
		if err := store.ImageChecked(image.ID, digest, failure, now); err != nil {
			serverLog("", store.LogError, "Could not save the check of image %s: %v", image.Reference, err)
			continue
		}
		if failure != "" {
			if failure != image.WatchError {
				serverLog("", store.LogWarning, "Could not check image %s (%s) for a new build: %s", image.Reference, image.Platform, failure)
			}
			continue
		}
		reason := ""
		switch {
		case image.Latest == nil:
			reason = "first scan"
		case image.TagDigest != "" && digest != image.TagDigest:
			reason = "new build pushed"
		default:
			if started, err := time.Parse(time.RFC3339, image.Latest.StartedAt); err == nil && now.Sub(started) >= rescanInterval {
				reason = "daily rescan"
			}
		}
		if reason == "" {
			continue
		}
		if _, err := store.QueueImageScan(image.ID, "watch: "+reason); err == nil {
			queued = true
			serverLog("", store.LogInfo, "Image %s (%s) queued for a scan: %s", image.Reference, image.Platform, reason)
		}
	}
	if queued {
		s.wakeImageScanner()
	}
}

// watchCheck returns what the image's tag points to now, or why that
// couldn't be found out.
func (s *Server) watchCheck(ctx context.Context, image store.Image) (digest, failure string) {
	ref, err := images.ParseReference(image.Reference)
	if err != nil {
		return "", err.Error()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	client, err := s.registryClient(ctx, ref.Registry)
	if err == nil {
		digest, err = s.images.tagDigest(ctx, client, ref)
	}
	if err != nil {
		return "", err.Error()
	}
	return digest, ""
}

func scanning(image store.Image) bool {
	return image.Latest != nil && (image.Latest.Status == store.ScanQueued || image.Latest.Status == store.ScanRunning)
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
		s.emit(notify.Message{Event: notify.EventScanFailed, Level: notify.LevelWarning,
			Title: fmt.Sprintf("Image %s: scan failed", image.Reference), Lines: []string{message},
			Link: link("/images/" + image.ID), Data: map[string]any{"image": image.Reference, "platform": image.Platform}})
	}
	ref, err := images.ParseReference(image.Reference)
	if err != nil {
		fail(err.Error())
		return
	}
	serverLog("", store.LogInfo, "Scan of image %s (%s) started by %s", image.Reference, image.Platform, record.StartedBy)
	ctx, cancel := context.WithTimeout(ctx, imageScanTimeout)
	defer cancel()
	client, err := s.registryClient(ctx, ref.Registry)
	if err != nil {
		fail(err.Error())
		return
	}
	inventory, resolved, err := s.images.read(ctx, client, ref, image.Platform)
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
	if err := store.FinishImageScan(record, resolved.TagDigest); err != nil {
		serverLog("", store.LogError, "Could not save the scan of image %s: %v", image.Reference, err)
		return
	}
	serverLog("", store.LogInfo, "Scan of image %s (%s) finished: %d critical, %d high, %d known to be exploited",
		image.Reference, image.Platform, record.Severity.Critical, record.Severity.High, record.Exploited)
	s.newImageVulnerabilities(image, record.ID, result)
}

// imageCVEs are the CVEs of an image's findings that are known to be
// exploited, and those that are critical; every finding has a fix or is
// known to be exploited.
func imageCVEs(result checks.ContainerResult) (exploited, critical map[string]bool) {
	exploited, critical = map[string]bool{}, map[string]bool{}
	for _, finding := range result.Findings {
		if strings.Contains(finding.Detail, "Known to be exploited") {
			exploited[finding.Rule] = true
		}
		if strings.EqualFold(finding.Severity, "CRITICAL") {
			critical[finding.Rule] = true
		}
	}
	return exploited, critical
}

// newImageVulnerabilities notifies about known exploited vulnerabilities, and
// critical ones, that the image's previous scan didn't have, as for hosts.
func (s *Server) newImageVulnerabilities(image store.Image, scanID string, result checks.ContainerResult) {
	exploited, critical := imageCVEs(result)
	previous, found, err := store.PreviousImageResult(image.ID, scanID)
	if err != nil {
		return
	}
	var before checks.ContainerResult
	if found {
		json.Unmarshal(previous.Result, &before)
	}
	oldExploited, oldCritical := imageCVEs(before)
	added := func(current, old map[string]bool) []string {
		var list []string
		for cve := range current {
			if !old[cve] {
				list = append(list, cve)
			}
		}
		sort.Strings(list)
		return list
	}
	target := link("/images/" + image.ID)
	data := func(cves []string) map[string]any {
		return map[string]any{"image": image.Reference, "platform": image.Platform, "digest": result.ImageID, "cves": cves}
	}
	if cves := added(exploited, oldExploited); len(cves) > 0 {
		s.emit(notify.Message{Event: notify.EventExploited, Level: notify.LevelCritical,
			Title: fmt.Sprintf("Image %s: %s known to be exploited", image.Reference, plural(len(cves), "new vulnerability", "new vulnerabilities")),
			Lines: []string{listCVEs(cves), "In CISA's Known Exploited Vulnerabilities catalog. Rebuild the image with the fixed packages."},
			Link:  target, Data: data(cves)})
	}
	if cves := added(critical, oldCritical); len(cves) > 0 {
		s.emit(notify.Message{Event: notify.EventCritical, Level: notify.LevelWarning,
			Title: fmt.Sprintf("Image %s: %s with a fix", image.Reference, plural(len(cves), "new critical vulnerability", "new critical vulnerabilities")),
			Lines: []string{listCVEs(cves), "A rebuild with updated packages, or a newer base image, fixes them."},
			Link:  target, Data: data(cves)})
	}
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
	// Watch is on unless the request turns it off.
	Watch *bool `json:"watch"`
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
	watch := request.Watch == nil || *request.Watch
	image, err := store.AddImage(ref.String(), platform, watch, s.actor(r))
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

// updateImage turns watching an image on or off.
func (s *Server) updateImage(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Watch *bool `json:"watch"`
	}
	if !readJSON(w, r, &request) {
		return
	}
	if request.Watch == nil {
		writeError(w, http.StatusBadRequest, errors.New("say whether to watch the image: {\"watch\": true}"))
		return
	}
	image, err := store.SetImageWatch(r.PathValue("id"), *request.Watch)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	state := "off"
	if image.Watch {
		state = "on"
	}
	s.audit(r, "image.watch", image.Reference, image.Platform+", "+state)
	writeJSON(w, http.StatusOK, image)
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
	// Kind is "basic" (the default) or "ecr": then Username is an AWS
	// access key ID and Secret its secret access key.
	Kind     string `json:"kind"`
	Username string `json:"username"`
	// Secret is a password or access token; empty keeps the saved one.
	Secret string `json:"secret"`
}

func (request registryLoginRequest) apply(login *store.RegistryLogin) error {
	host, err := images.RegistryHost(request.Registry)
	if err != nil {
		return err
	}
	kind := request.Kind
	switch kind {
	case "", store.LoginBasic:
		kind = store.LoginBasic
	case store.LoginECR:
		if _, ok := images.ECRRegion(host); !ok {
			return errors.New("an AWS access key works only for an Amazon ECR registry, such as 123456789012.dkr.ecr.eu-north-1.amazonaws.com")
		}
	default:
		return errors.New(`the kind is "basic" or "ecr"`)
	}
	username := strings.TrimSpace(request.Username)
	if username == "" || len(username) > 256 {
		return errors.New("give the username (for ECR, the access key ID), up to 256 characters")
	}
	if len(request.Secret) > 8192 {
		return errors.New("the password or token is longer than 8192 characters")
	}
	if login.ID == "" && request.Secret == "" {
		return errors.New("give the password or access token")
	}
	if login.ID != "" && request.Secret == "" && (login.Kind != kind || login.Registry != host) {
		return errors.New("give the password or key again when changing the registry or the kind of login")
	}
	secret := request.Secret
	if kind == store.LoginECR {
		// AWS keys never contain spaces: a pasted line break or space would
		// only make AWS refuse the signature.
		secret = strings.TrimSpace(secret)
	}
	login.Registry, login.Kind, login.Username, login.Secret = host, kind, username, secret
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
	detail := "user " + saved.Username
	if saved.Kind == store.LoginECR {
		detail = "AWS access key " + saved.Username
	}
	s.audit(r, action, saved.Registry, detail)
	s.recheckImagesIn(saved.Registry)
	writeJSON(w, status, saved)
}

// recheckImagesIn clears the watch failures of a registry's images and
// checks their tags at once: a changed login may have fixed them.
func (s *Server) recheckImagesIn(registry string) {
	list, err := store.Images()
	if err != nil {
		return
	}
	due := false
	for _, image := range list {
		if ref, err := images.ParseReference(image.Reference); err == nil && ref.Registry == registry {
			if store.RecheckImage(image.ID) == nil {
				due = true
			}
		}
	}
	if due {
		s.wakeImageScanner()
	}
}

// registryLoginCheck is the result of logging in with a saved login.
type registryLoginCheck struct {
	// Status is "ok" (the registry accepted the login), "failed", or
	// "unchecked" (the registry didn't ask for a login).
	Status    string `json:"status"`
	Message   string `json:"message"`
	CheckedAt string `json:"checked_at"`
}

// checkRegistryLogin logs in to the registry with a saved login, the way a
// scan would, and says whether the registry accepts it.
func (s *Server) checkRegistryLogin(w http.ResponseWriter, r *http.Request) {
	login, err := store.GetRegistryLogin(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	result := registryLoginCheck{Status: "ok", Message: "The registry accepted the login.", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	err = s.tryRegistryLogin(ctx, login)
	switch {
	case errors.Is(err, images.ErrLoginNotAsked):
		result.Status, result.Message = "unchecked", "The registry answers without a login, so it couldn't check this one. DeaconGuard still uses it for images that need it."
	case err != nil:
		result.Status, result.Message = "failed", explainLoginFailure(login, err)
	case login.Kind == store.LoginECR:
		result.Message = "AWS accepted the access key, and the registry accepted the login it gave."
	}
	writeJSON(w, http.StatusOK, result)
}

// explainLoginFailure says in plain words why a login failed, and what to
// change, with the registry's or AWS's own answer.
func explainLoginFailure(login store.RegistryLogin, err error) string {
	text := err.Error()
	if login.Kind == store.LoginECR {
		for _, known := range []struct{ code, advice string }{
			{"InvalidSignatureException", "AWS refused the secret access key: it doesn't belong to this access key ID. Paste the secret again, without spaces, or create a new access key."},
			{"UnrecognizedClientException", "AWS doesn't know this access key ID: it was deleted, deactivated, or mistyped."},
			{"AccessDeniedException", "AWS accepted the key, but its user may not call ecr:GetAuthorizationToken. Give it read access to ECR."},
			{"ExpiredTokenException", "The key has expired. Create a new access key."},
		} {
			if strings.Contains(text, known.code) {
				return known.advice + " (" + text + ")"
			}
		}
		if errors.Is(err, images.ErrUnauthorized) && !strings.Contains(text, "AWS answered") {
			return "AWS gave a registry login, but the registry refused it: the key's user may not be allowed ecr:BatchGetImage and ecr:GetDownloadUrlForLayer. (" + text + ")"
		}
		return text
	}
	if errors.Is(err, images.ErrUnauthorized) {
		return "The registry refused this login: check the username and the password or token, and that the token may read images. (" + text + ")"
	}
	return text
}

func (s *Server) tryRegistryLogin(ctx context.Context, login store.RegistryLogin) error {
	credentials := images.Credentials{Username: login.Username, Password: login.Secret}
	if login.Kind == store.LoginECR {
		// A fresh token, so the saved key itself is checked.
		token, _, err := images.ECRToken(ctx, s.images.http, login.Registry, s.images.ecrEndpoint, login.Username, login.Secret, time.Now())
		if err != nil {
			return err
		}
		credentials = token
	}
	client := images.NewClient(func(host string) (images.Credentials, bool) { return credentials, host == login.Registry })
	return s.images.checkLogin(ctx, client, login.Registry)
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
