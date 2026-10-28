package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"deaconguard/internal/images"
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
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	TagPattern string `json:"tag_pattern"`
	Platform   string `json:"platform"`
	Keep       int    `json:"keep"`
}

// maxKeep caps how many of a repository's newest tags a watch keeps
// scanning.
const maxKeep = 20

func (request repositoryWatchRequest) check() error {
	if _, err := images.CompileTagPattern(request.TagPattern); err != nil {
		return err
	}
	if request.Keep < 1 || request.Keep > maxKeep {
		return fmt.Errorf("keep between 1 and %d of the newest matching tags", maxKeep)
	}
	return nil
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
	if err := request.check(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	watch, err := store.AddRepositoryWatch(store.RepositoryWatch{Registry: registry, Repository: repository, TagPattern: request.TagPattern,
		Platform: request.Platform, Keep: request.Keep, CreatedBy: s.actor(r)})
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
	request := repositoryWatchRequest{TagPattern: current.TagPattern, Keep: current.Keep}
	if !readJSON(w, r, &request) {
		return
	}
	if err := request.check(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	watch, err := store.UpdateRepositoryWatch(current.ID, request.TagPattern, request.Keep)
	if errors.Is(err, store.ErrRepositoryWatchExists) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
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
	return fmt.Sprintf("tags %s, newest %d, %s", pattern, watch.Keep, watch.Platform)
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
// the server first saw them, and on a watch's first check, when it has seen
// none, in natural order (v1.10 after v1.9).
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
	for index, tag := range newest {
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
		reason := "watch: new push of " + tag.Tag
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
		}
		record = append(record, store.RepositoryTag{Tag: tag.Tag, Digest: digest, PushedAt: pushed})
	}
	if err := store.SaveRepositoryTags(watch.ID, record); err != nil {
		return fail(err.Error())
	}
	store.RepositoryWatchChecked(watch.ID, "", now)
	return queued
}
