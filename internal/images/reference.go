// Package images reads container images from registries, as data: the
// manifest and the layers through the registry API (the one docker pull
// uses), keeping only the files that say what is installed. Nothing in an
// image is run. Layers are checked against their digests, and what was
// read from each is cached by digest, so base layers that many images share
// are read once.
package images

import (
	"fmt"
	"regexp"
	"strings"
)

// Reference names an image: registry, repository, and a tag or digest.
type Reference struct {
	// Registry is the registry's host (and port), such as ghcr.io;
	// Docker Hub is registry-1.docker.io.
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

const dockerHub = "registry-1.docker.io"

var (
	digestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	tagPattern        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	repositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	registryPattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]{1,5})?$`)
)

// ParseReference reads an image reference as docker understands it:
// "nginx" is docker.io/library/nginx:latest; "ghcr.io/acme/shop:4.2",
// "registry.example.com:5000/team/app@sha256:…".
func ParseReference(text string) (Reference, error) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 512 || strings.ContainsAny(text, " \t\n") {
		return Reference{}, fmt.Errorf("%q is not an image reference", text)
	}
	var ref Reference
	if name, digest, found := strings.Cut(text, "@"); found {
		if !digestPattern.MatchString(digest) {
			return Reference{}, fmt.Errorf("%q: the digest must be sha256:<64 hex digits>", text)
		}
		ref.Digest, text = digest, name
	}
	// A registry is the first part when it has a dot or a port, or is localhost.
	if first, rest, found := strings.Cut(text, "/"); found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		ref.Registry, text = first, rest
	}
	if colon := strings.LastIndex(text, ":"); colon > strings.LastIndex(text, "/") {
		ref.Tag, text = text[colon+1:], text[:colon]
		if !tagPattern.MatchString(ref.Tag) {
			return Reference{}, fmt.Errorf("%q: invalid tag %q", text, ref.Tag)
		}
	}
	switch ref.Registry {
	case "", "docker.io", "index.docker.io", "registry.hub.docker.com":
		ref.Registry = dockerHub
		if !strings.Contains(text, "/") {
			text = "library/" + text
		}
	}
	if !registryPattern.MatchString(ref.Registry) {
		return Reference{}, fmt.Errorf("%q: invalid registry %q", text, ref.Registry)
	}
	if !repositoryPattern.MatchString(text) {
		return Reference{}, fmt.Errorf("%q: invalid repository name", text)
	}
	ref.Repository = text
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}
	return ref, nil
}

// String writes the reference the way people write it.
func (r Reference) String() string {
	name := r.Registry + "/" + r.Repository
	if r.Registry == dockerHub {
		name = strings.TrimPrefix(r.Repository, "library/")
	}
	if r.Tag != "" {
		name += ":" + r.Tag
	}
	if r.Digest != "" {
		name += "@" + r.Digest
	}
	return name
}

// reference is what the registry API calls a manifest: the digest when
// there is one, or the tag.
func (r Reference) reference() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// IsDockerHub reports whether registry is Docker Hub, which limits how many
// manifests may be read.
func IsDockerHub(registry string) bool { return registry == dockerHub }

// RegistryHost names a registry as references do, for saved logins: "docker.io"
// is registry-1.docker.io, and a scheme or trailing slash is dropped.
func RegistryHost(text string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(text))
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	switch host {
	case "docker.io", "index.docker.io", "registry.hub.docker.com", "hub.docker.com":
		host = dockerHub
	}
	if host == "" || !registryPattern.MatchString(host) {
		return "", fmt.Errorf("%q is not a registry host, such as ghcr.io or registry.example.com:5000", text)
	}
	return host, nil
}

// Platforms are the platforms an image can be checked for.
var Platforms = []string{"linux/amd64", "linux/arm64", "linux/arm/v7", "linux/386", "linux/ppc64le", "linux/s390x"}
