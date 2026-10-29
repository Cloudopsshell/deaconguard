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
	"deaconguard/internal/images"
	"deaconguard/internal/notify"
	"deaconguard/internal/store"
)

// Repositories and repository watches: browsing what a registry login can
// see, and scanning each new push to a repository whose tag matches a
// pattern.

// listRepositoriesFunc and listTagsFunc list a registry's repositories and
// a repository's tags with its saved login; tests replace them.
type (
	listRepositoriesFunc func(ctx context.Context, s *Server, login store.RegistryLogin) ([]string, error)
	listTagsFunc         func(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error)
)

// listRepositories uses the ECR API for an ECR login, which lists every
// repository, and the registry API's catalog otherwise, which some
// registries, such as Docker Hub and GHCR, refuse.
func listRepositories(ctx context.Context, s *Server, login store.RegistryLogin) ([]string, error) {
	if login.Kind == store.LoginECR {
		return s.ecrAPI(login).Repositories(ctx)
	}
	client, err := s.registryClient(ctx, login.Registry)
	if err != nil {
		return nil, err
	}
	return client.Repositories(ctx, login.Registry)
}

// listTags uses the ECR API for an ECR registry, which also says when each
// image was pushed, and the registry API otherwise.
func listTags(ctx context.Context, s *Server, registry, repository string) ([]images.TagInfo, error) {
	login, found, err := store.RegistryLoginFor(registry)
	if err != nil {
		return nil, err
	}
	if found && login.Kind == store.LoginECR {
		return s.ecrAPI(login).Tags(ctx, repository)
	}
	client, err := s.registryClient(ctx, registry)
	if err != nil {
		return nil, err
	}
	return client.Tags(ctx, registry, repository)
}

// createdFunc reads when a tag's image was built; tests replace it.
type createdFunc func(ctx context.Context, client *images.Client, ref images.Reference, platform string) (time.Time, error)

func created(ctx context.Context, client *images.Client, ref images.Reference, platform string) (time.Time, error) {
	return client.Created(ctx, ref, platform)
}

const (
	// maxBuiltReads caps how many tags' build times one listing reads, and
	// builtReaders how many at once.
	maxBuiltReads = 100
	builtReaders  = 6
	// builtTimeKept is how long a build time read is reused, so that
	// previewing a watch doesn't read it again on each change.
	builtTimeKept = 10 * time.Minute
)

type builtTime struct {
	created time.Time
	read    time.Time
}

// readBuildTimes fills in when the images of a repository's tags were built,
// for the tags want picks that have no push time, so they can be ordered
// where the registry doesn't say when each was pushed. It reads at most
// maxBuiltReads, the newest by version, and none on Docker Hub, which limits
// reads. A tag it can't read keeps its place by version.
func (s *Server) readBuildTimes(ctx context.Context, registry, repository, platform string, tags []images.TagInfo, want func(images.TagInfo) bool) {
	if images.IsDockerHub(registry) {
		return
	}
	var candidates []images.TagInfo
	for _, tag := range tags {
		if tag.PushedAt.IsZero() && want(tag) {
			candidates = append(candidates, tag)
		}
	}
	// One tag needs no order.
	if len(candidates) < 2 {
		return
	}
	candidates, _ = images.MatchTags(candidates, "")
	candidates = candidates[:min(len(candidates), maxBuiltReads)]
	client, err := s.registryClient(ctx, registry)
	if err != nil {
		return
	}
	found := make(map[string]time.Time, len(candidates))
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan string)
	for range min(builtReaders, len(candidates)) {
		wg.Go(func() {
			for tag := range work {
				ref := images.Reference{Registry: registry, Repository: repository, Tag: tag}
				key := ref.String() + " " + platform
				s.images.mu.Lock()
				cached, ok := s.images.builtTimes[key]
				s.images.mu.Unlock()
				if !ok || time.Since(cached.read) > builtTimeKept {
					when, err := s.images.created(ctx, client, ref, platform)
					if err != nil {
						continue
					}
					cached = builtTime{created: when, read: time.Now()}
					s.images.mu.Lock()
					for old, entry := range s.images.builtTimes {
						if time.Since(entry.read) > builtTimeKept {
							delete(s.images.builtTimes, old)
						}
					}
					s.images.builtTimes[key] = cached
					s.images.mu.Unlock()
				}
				mu.Lock()
				found[tag] = cached.created
				mu.Unlock()
			}
		})
	}
	for _, tag := range candidates {
		work <- tag.Tag
	}
	close(work)
	wg.Wait()
	for index := range tags {
		if when, ok := found[tags[index].Tag]; ok {
			tags[index].Created = when
		}
	}
}

func (s *Server) ecrAPI(login store.RegistryLogin) images.ECRAPI {
	return images.ECRAPI{Client: s.images.http, Registry: login.Registry, Endpoint: s.images.ecrEndpoint, KeyID: login.Username, Secret: login.Secret}
}

// explainListingFailure says why a listing failed, in plain words.
func explainListingFailure(login store.RegistryLogin, err error) string {
	text := err.Error()
	if errors.Is(err, images.ErrListingRefused) {
		return "This registry doesn't list its repositories for this login. Type the repository's name instead, such as team/app."
	}
	if login.Kind == store.LoginECR && strings.Contains(text, "AccessDeniedException") {
		return "AWS refused to list: the key's user also needs ecr:DescribeRepositories and ecr:DescribeImages to browse and watch repositories. (" + text + ")"
	}
	return explainLoginFailure(login, err)
}

// browseRepositories lists the repositories a saved login can see.
func (s *Server) browseRepositories(w http.ResponseWriter, r *http.Request) {
	login, err := store.GetRegistryLogin(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	type answer struct {
		Registry     string   `json:"registry"`
		Repositories []string `json:"repositories"`
		// Listed is false when the registry won't list them; Message says why.
		Listed  bool   `json:"listed"`
		Message string `json:"message,omitempty"`
	}
	names, err := s.images.listRepositories(ctx, s, login)
	if err != nil {
		writeJSON(w, http.StatusOK, answer{Registry: login.Registry, Repositories: []string{}, Message: explainListingFailure(login, err)})
		return
	}
	writeJSON(w, http.StatusOK, answer{Registry: login.Registry, Repositories: names, Listed: true})
}

// browseTags lists a repository's tags, newest first, and which ones a tag
// pattern matches, so the dashboard can preview a watch.
func (s *Server) browseTags(w http.ResponseWriter, r *http.Request) {
	login, err := store.GetRegistryLogin(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	repository := strings.Trim(strings.TrimSpace(r.URL.Query().Get("repository")), "/")
	if _, err := images.ParseReference(login.Registry + "/" + repository); repository == "" || err != nil {
		writeError(w, http.StatusBadRequest, errors.New("give a repository name, such as team/app"))
		return
	}
	pattern := r.URL.Query().Get("pattern")
	if _, err := images.CompileTagPattern(pattern); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	tags, err := s.images.listTags(ctx, s, login.Registry, repository)
	if err != nil {
		writeError(w, http.StatusBadGateway, errors.New(explainListingFailure(login, err)))
		return
	}
	// Previewing a watch for a platform orders the tags it matches as the
	// watch's first check will.
	if platform := r.URL.Query().Get("platform"); platform != "" {
		match, _ := images.CompileTagPattern(pattern)
		s.readBuildTimes(ctx, login.Registry, repository, platform, tags, func(tag images.TagInfo) bool { return match.MatchString(tag.Tag) })
	}
	all, _ := images.MatchTags(tags, "")
	matched, _ := images.MatchTags(tags, pattern)
	matches := make(map[string]bool, len(matched))
	for _, tag := range matched {
		matches[tag.Tag] = true
	}
	type tagView struct {
		images.TagInfo
		Matches   bool   `json:"matches"`
		Reference string `json:"reference"`
	}
	view := make([]tagView, 0, len(all))
	for _, tag := range all {
		ref := images.Reference{Registry: login.Registry, Repository: repository, Tag: tag.Tag}
		view = append(view, tagView{TagInfo: tag, Matches: matches[tag.Tag], Reference: ref.String()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"repository": repository, "tags": view, "matched": len(matched)})
}

type repositoryWatchRequest struct {
	Registry       string   `json:"registry"`
	Repository     string   `json:"repository"`
	TagPattern     string   `json:"tag_pattern"`
	Platform       string   `json:"platform"`
	Keep           int      `json:"keep"`
	History        int      `json:"history"`
	NotifyLevel    string   `json:"notify_level"`
	NotifyChannels []string `json:"notify_channels"`
}

const (
	// maxKeep caps how many of a repository's newest tags a watch keeps
	// scanning.
	maxKeep = 20
	// defaultHistory and maxHistory are how many of the images a watch
	// added it keeps, with their scans.
	defaultHistory = 50
	maxHistory     = 500
)

func (request *repositoryWatchRequest) check() error {
	if _, err := images.CompileTagPattern(request.TagPattern); err != nil {
		return err
	}
	if request.Keep < 1 || request.Keep > maxKeep {
		return fmt.Errorf("keep between 1 and %d of the newest matching tags", maxKeep)
	}
	if request.History < request.Keep || request.History > maxHistory {
		return fmt.Errorf("keep the history of between %d (the tags it scans) and %d images", request.Keep, maxHistory)
	}
	if !slices.Contains(store.NotifyLevels, request.NotifyLevel) {
		return fmt.Errorf("the report setting is one of %s", strings.Join(store.NotifyLevels, ", "))
	}
	if request.NotifyChannels == nil {
		request.NotifyChannels = []string{}
	}
	if len(request.NotifyChannels) > 0 {
		channels, err := store.Channels()
		if err != nil {
			return err
		}
		for _, id := range request.NotifyChannels {
			if !slices.ContainsFunc(channels, func(channel store.Channel) bool { return channel.ID == id }) {
				return fmt.Errorf("unknown notification channel %q", id)
			}
		}
	}
	return nil
}

func (request repositoryWatchRequest) settings() store.RepositoryWatch {
	return store.RepositoryWatch{TagPattern: request.TagPattern, Keep: request.Keep, History: request.History,
		NotifyLevel: request.NotifyLevel, NotifyChannels: request.NotifyChannels}
}

func (s *Server) listRepositoryWatches(w http.ResponseWriter, r *http.Request) {
	list, err := store.RepositoryWatches()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) addRepositoryWatch(w http.ResponseWriter, r *http.Request) {
	var request repositoryWatchRequest
	if !readJSON(w, r, &request) {
		return
	}
	registry, err := images.RegistryHost(request.Registry)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	repository := strings.Trim(strings.TrimSpace(request.Repository), "/")
	if _, err := images.ParseReference(registry + "/" + repository); repository == "" || err != nil {
		writeError(w, http.StatusBadRequest, errors.New("give a repository name, such as team/app"))
		return
	}
	if request.Platform == "" {
		request.Platform = "linux/amd64"
	}
	if !slices.Contains(images.Platforms, request.Platform) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("the platform is one of %s", strings.Join(images.Platforms, ", ")))
		return
	}
	if request.Keep == 0 {
		request.Keep = 5
	}
	if request.History == 0 {
		request.History = max(defaultHistory, request.Keep)
	}
	if request.NotifyLevel == "" {
		request.NotifyLevel = "any"
	}
	if err := request.check(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	watch := request.settings()
	watch.Registry, watch.Repository, watch.Platform, watch.CreatedBy = registry, repository, request.Platform, s.actor(r)
	watch, err = store.AddRepositoryWatch(watch)
	if errors.Is(err, store.ErrRepositoryWatchExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "repository_watch.add", registry+"/"+repository, describeWatch(watch))
	s.wakeImageScanner()
	writeJSON(w, http.StatusCreated, watch)
}

func (s *Server) updateRepositoryWatch(w http.ResponseWriter, r *http.Request) {
	current, err := store.GetRepositoryWatch(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	request := repositoryWatchRequest{TagPattern: current.TagPattern, Keep: current.Keep, History: current.History,
		NotifyLevel: current.NotifyLevel, NotifyChannels: current.NotifyChannels}
	if !readJSON(w, r, &request) {
		return
	}
	if err := request.check(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	watch, err := store.UpdateRepositoryWatch(current.ID, request.settings())
	if errors.Is(err, store.ErrRepositoryWatchExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if watch.History < current.History {
		store.RemoveOldWatchImages(watch.ID, watch.History)
		watch, _ = store.GetRepositoryWatch(watch.ID)
	}
	s.audit(r, "repository_watch.update", watch.Registry+"/"+watch.Repository, describeWatch(watch))
	s.wakeImageScanner()
	writeJSON(w, http.StatusOK, watch)
}

func (s *Server) deleteRepositoryWatch(w http.ResponseWriter, r *http.Request) {
	watch, err := store.DeleteRepositoryWatch(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.audit(r, "repository_watch.delete", watch.Registry+"/"+watch.Repository, describeWatch(watch))
	w.WriteHeader(http.StatusNoContent)
}

// repositoryWatchDetail is a watch with its builds: every scan of the
// images it added, newest first.
type repositoryWatchDetail struct {
	store.RepositoryWatch
	Builds []store.WatchBuild `json:"builds"`
}

func (s *Server) repositoryWatch(w http.ResponseWriter, r *http.Request) {
	watch, err := store.GetRepositoryWatch(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	builds, err := store.WatchBuilds(watch.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, repositoryWatchDetail{RepositoryWatch: watch, Builds: builds})
}

// reportChannel is a notification channel a watch's reports can go to,
// named for operators, who can't read the channels' settings.
type reportChannel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	// Subscribed says whether it takes image scan reports at all.
	Subscribed bool `json:"subscribed"`
}

func (s *Server) reportChannels(w http.ResponseWriter, r *http.Request) {
	channels, err := store.Channels()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	list := make([]reportChannel, 0, len(channels))
	for _, channel := range channels {
		list = append(list, reportChannel{ID: channel.ID, Name: channel.Name, Kind: channel.Kind, Enabled: channel.Enabled,
			Subscribed: slices.Contains(channel.Events, notify.EventImageReport)})
	}
	writeJSON(w, http.StatusOK, list)
}

// checkRepositoryWatchNow checks a watch at once.
func (s *Server) checkRepositoryWatchNow(w http.ResponseWriter, r *http.Request) {
	watch, err := store.GetRepositoryWatch(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if s.checkRepositoryWatch(ctx, watch, time.Now()) {
		s.wakeImageScanner()
	}
	watch, _ = store.GetRepositoryWatch(watch.ID)
	writeJSON(w, http.StatusOK, watch)
}

func describeWatch(watch store.RepositoryWatch) string {
	pattern := watch.TagPattern
	if pattern == "" {
		pattern = "every tag"
	}
	return fmt.Sprintf("tags %s, newest %d, history %d, reports %s, %s", pattern, watch.Keep, watch.History, watch.NotifyLevel, watch.Platform)
}

// checkRepositoryWatches checks each repository watch that is due, as
// often as watched images.
func (s *Server) checkRepositoryWatches(ctx context.Context, now time.Time) {
	list, err := store.RepositoryWatches()
	if err != nil {
		serverLog("", store.LogError, "Could not read the repository watches: %v", err)
		return
	}
	queued := false
	for _, watch := range list {
		if ctx.Err() != nil {
			return
		}
		if checked, err := time.Parse(time.RFC3339, watch.CheckedAt); err == nil && now.Sub(checked) < watchInterval {
			continue
		}
		if s.checkRepositoryWatch(ctx, watch, now) {
			queued = true
		}
	}
	if queued {
		s.wakeImageScanner()
	}
}

// checkRepositoryWatch lists a watched repository's tags, adds the images of
// the newest matching tags that are new or were pushed again, queues their
// scans, and stops watching the older ones. It says whether it queued any.
//
// Tags are ordered by push time where the registry says (ECR), else by when
// the server first saw them. On a watch's first check, when it has seen
// none, and among tags first seen together, they are ordered by when their
// images were built, then in natural order (v1.10 after v1.9). The first
// check records the build times, so later checks keep that order.
func (s *Server) checkRepositoryWatch(ctx context.Context, watch store.RepositoryWatch, now time.Time) bool {
	fail := func(message string) bool {
		if message != watch.WatchError {
			serverLog("", store.LogWarning, "Could not check repository %s/%s for new pushes: %s", watch.Registry, watch.Repository, message)
		}
		store.RepositoryWatchChecked(watch.ID, message, now)
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tags, err := s.images.listTags(ctx, s, watch.Registry, watch.Repository)
	if err != nil {
		return fail(err.Error())
	}
	known, err := store.RepositoryTags(watch.ID)
	if err != nil {
		return fail(err.Error())
	}
	first := len(known) == 0
	match, err := images.CompileTagPattern(watch.TagPattern)
	if err != nil {
		return fail(err.Error())
	}
	s.readBuildTimes(ctx, watch.Registry, watch.Repository, watch.Platform, tags, func(tag images.TagInfo) bool {
		_, seen := known[tag.Tag]
		return !seen && match.MatchString(tag.Tag)
	})
	for index := range tags {
		if !tags[index].PushedAt.IsZero() {
			continue
		}
		if seen, ok := known[tags[index].Tag]; ok {
			tags[index].PushedAt, _ = time.Parse(time.RFC3339, seen.PushedAt)
		} else if !first {
			tags[index].PushedAt = now.UTC()
		}
	}
	matched, err := images.MatchTags(tags, watch.TagPattern)
	if err != nil {
		return fail(err.Error())
	}
	newest := matched[:min(watch.Keep, len(matched))]
	var client *images.Client
	keep := make(map[string]bool, len(newest))
	queued := false
	// Oldest first, so images are added in push order and the history
	// removes the oldest.
	for index := len(newest) - 1; index >= 0; index-- {
		tag := newest[index]
		ref := images.Reference{Registry: watch.Registry, Repository: watch.Repository, Tag: tag.Tag}
		reference := ref.String()
		keep[reference] = true
		if tag.Digest == "" {
			// The registry API doesn't give digests with tags; ask for the
			// newest ones only.
			if client == nil {
				if client, err = s.registryClient(ctx, watch.Registry); err != nil {
					return fail(err.Error())
				}
			}
			if newest[index].Digest, err = s.images.tagDigest(ctx, client, ref); err != nil {
				return fail(err.Error())
			}
			tag = newest[index]
		}
		seen, ok := known[tag.Tag]
		if ok && seen.Digest == tag.Digest {
			continue
		}
		image, added, err := store.WatchImage(watch.ID, reference, watch.Platform, "watch: "+watch.Registry+"/"+watch.Repository)
		if err != nil {
			return fail(err.Error())
		}
		if scanning(image) || (!added && image.TagDigest == tag.Digest) {
			continue
		}
		reason := newPushReason + tag.Tag
		if first {
			reason = "watch: repository added"
		}
		if _, err := store.QueueImageScan(image.ID, reason); err == nil {
			queued = true
			serverLog("", store.LogInfo, "Image %s (%s) queued for a scan: %s", reference, watch.Platform, strings.TrimPrefix(reason, "watch: "))
		}
	}
	if err := store.StopWatchingOlderImages(watch.ID, keep); err != nil {
		return fail(err.Error())
	}
	if removed, err := store.RemoveOldWatchImages(watch.ID, watch.History); err != nil {
		return fail(err.Error())
	} else if removed > 0 {
		serverLog("", store.LogInfo, "Removed %s of repository %s/%s beyond its history of %d", plural(removed, "older image", "older images"),
			watch.Registry, watch.Repository, watch.History)
	}
	digests := make(map[string]string, len(newest))
	for _, tag := range newest {
		digests[tag.Tag] = tag.Digest
	}
	record := make([]store.RepositoryTag, 0, len(matched))
	for _, tag := range matched {
		digest := digests[tag.Tag]
		if digest == "" {
			digest = tag.Digest
		}
		pushed := ""
		if !tag.PushedAt.IsZero() {
			pushed = tag.PushedAt.UTC().Format(time.RFC3339)
		} else if !tag.Created.IsZero() {
			pushed = tag.Created.UTC().Format(time.RFC3339)
		}
		record = append(record, store.RepositoryTag{Tag: tag.Tag, Digest: digest, PushedAt: pushed})
	}
	if err := store.SaveRepositoryTags(watch.ID, record); err != nil {
		return fail(err.Error())
	}
	store.RepositoryWatchChecked(watch.ID, "", now)
	return queued
}

// newPushReason starts the reason of a scan a repository watch queued for a
// new push; the scan's report goes out when it finishes.
const newPushReason = "watch: new push of "

// reports says whether a scan's counts reach a watch's report setting.
func reports(level string, scan store.ImageScan) bool {
	counts := scan.Severity
	switch level {
	case "any":
		return true
	case "low":
		return counts.Critical+counts.High+counts.Medium+counts.Low > 0
	case "medium":
		return counts.Critical+counts.High+counts.Medium > 0
	case "high":
		return counts.Critical+counts.High > 0
	case "critical":
		return counts.Critical > 0
	case "exploited":
		return scan.Exploited > 0
	}
	return false
}

// imageVulnerabilities are a scan's vulnerabilities, most urgent first:
// all of them, or only those with a fix from servers before 1.8.0.
func imageVulnerabilities(result checks.ContainerResult) []checks.Finding {
	if len(result.Vulnerabilities) > 0 {
		return result.Vulnerabilities
	}
	return result.Findings
}

// reportedCVEs is how many CVEs a report names at most.
const reportedCVEs = 5

// reportNewPush sends a watched repository's report of a new push's scan:
// its counts, how it compares with the repository's previous build, and its
// most urgent vulnerabilities, when the watch's report setting allows.
func (s *Server) reportNewPush(image store.Image, scan store.ImageScan, result checks.ContainerResult) {
	watch, err := store.GetRepositoryWatch(image.RepositoryWatchID)
	if err != nil || !reports(watch.NotifyLevel, scan) {
		return
	}
	tag := strings.TrimPrefix(scan.StartedBy, newPushReason)
	counts := scan.Severity
	total := counts.Critical + counts.High + counts.Medium + counts.Low + counts.Unknown
	level := notify.LevelInfo
	switch {
	case scan.Exploited > 0 || counts.Critical > 0:
		level = notify.LevelCritical
	case counts.High > 0:
		level = notify.LevelWarning
	}
	title := fmt.Sprintf("New push of %s/%s:%s: no vulnerabilities", watch.Registry, watch.Repository, tag)
	if total > 0 {
		title = fmt.Sprintf("New push of %s/%s:%s: %d critical, %d high", watch.Registry, watch.Repository, tag, counts.Critical, counts.High)
		if scan.Exploited > 0 {
			title += fmt.Sprintf(", %d known to be exploited", scan.Exploited)
		}
	}
	lines := []string{
		fmt.Sprintf("Critical %d · High %d · Medium %d · Low %d · Unknown %d", counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown),
		fmt.Sprintf("%d known to be exploited · %d fixed by an update", scan.Exploited, scan.Fixable),
	}
	current := map[string]bool{}
	for _, finding := range imageVulnerabilities(result) {
		current[finding.Rule] = true
	}
	data := map[string]any{
		"image": image.Reference, "platform": image.Platform, "digest": scan.Digest, "repository": watch.Registry + "/" + watch.Repository,
		"tag": tag, "severity": counts, "exploited": scan.Exploited, "fixable": scan.Fixable,
	}
	// A tag pushed again compares with what it held before; a new tag with
	// the image added before it.
	previous, found, err := store.PreviousImageResult(image.ID, scan.ID)
	if err == nil && !found {
		previous, found, err = store.PreviousWatchResult(watch.ID, image.ID)
	}
	if err == nil && found {
		var before checks.ContainerResult
		json.Unmarshal(previous.Result, &before)
		old := map[string]bool{}
		for _, finding := range imageVulnerabilities(before) {
			old[finding.Rule] = true
		}
		var added, fixed []string
		for cve := range current {
			if !old[cve] {
				added = append(added, cve)
			}
		}
		for cve := range old {
			if !current[cve] {
				fixed = append(fixed, cve)
			}
		}
		sort.Strings(added)
		sort.Strings(fixed)
		previousReference := previous.ImageID
		if before, err := store.GetImage(previous.ImageID); err == nil {
			previousReference = before.Reference
		}
		against := previousReference
		if previous.ImageID == image.ID {
			against = "the previous push of " + tag
		}
		line := fmt.Sprintf("Compared with %s: %d new, %d fixed", against, len(added), len(fixed))
		if len(added) > 0 {
			line += ". New: " + listCVEs(added)
		}
		lines = append(lines, line)
		data["previous"] = previousReference
		data["new_cves"], data["fixed_cves"] = nonNil(added), nonNil(fixed)
	}
	var top []string
	named := map[string]bool{}
	for _, finding := range imageVulnerabilities(result) {
		if len(top) == reportedCVEs {
			break
		}
		if named[finding.Rule] {
			continue
		}
		named[finding.Rule] = true
		item := fmt.Sprintf("%s (%s", finding.Rule, strings.ToLower(finding.Severity))
		if finding.Package != "" {
			item += ", " + finding.Package + " " + finding.Version
			if finding.Fixed != "" {
				item += " → " + finding.Fixed
			}
		}
		top = append(top, item+")")
	}
	if len(top) > 0 {
		lines = append(lines, "Most urgent: "+strings.Join(top, "; "))
	}
	data["top"] = nonNil(top)
	s.emit(notify.Message{Event: notify.EventImageReport, Level: level, Title: title, Lines: lines,
		Link: link("/images/repositories/" + watch.ID), Data: data, Channels: watch.NotifyChannels})
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}
