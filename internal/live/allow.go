package live

import "strings"

// Allow is an allowlist rule: alerts it matches are expected where it
// applies, so they're skipped and only counted. Rule is required; every
// other field left empty matches anything.
type Allow struct {
	ID   int64  `json:"id"`
	Rule string `json:"rule"`
	// Program is the program's path, as alerts name it.
	Program string `json:"program,omitempty"`
	// Path is the file, module or process an alert names.
	Path string `json:"path,omitempty"`
	// Image matches the container's image; one without a tag or digest
	// matches every tag of it.
	Image     string `json:"image,omitempty"`
	Container string `json:"container,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// Matches reports whether the rule covers the alert. Test alerts are never
// skipped.
func (a Allow) Matches(alert Alert) bool {
	if alert.Test || a.Rule == "" || a.Rule != alert.Rule {
		return false
	}
	if a.Program != "" && a.Program != alert.Program {
		return false
	}
	if a.Path != "" && a.Path != alert.Path {
		return false
	}
	if a.Container != "" && a.Container != alert.Container {
		return false
	}
	if a.Namespace != "" && a.Namespace != alert.Namespace {
		return false
	}
	return a.Image == "" || imageMatches(a.Image, alert.Image)
}

// imageMatches compares an image as written in a rule with a container's:
// exactly, or by repository when the rule names no tag or digest.
func imageMatches(rule, image string) bool {
	if rule == image {
		return true
	}
	if image == "" || hasTag(rule) {
		return false
	}
	return repository(image) == rule
}

// hasTag reports whether an image reference names a tag or digest. A colon
// before the last slash belongs to a registry's port.
func hasTag(image string) bool {
	if strings.Contains(image, "@") {
		return true
	}
	return strings.LastIndexByte(image, ':') > strings.LastIndexByte(image, '/')
}

// repository is an image reference without its tag and digest.
func repository(image string) string {
	if at := strings.IndexByte(image, '@'); at >= 0 {
		image = image[:at]
	}
	if colon := strings.LastIndexByte(image, ':'); colon > strings.LastIndexByte(image, '/') {
		image = image[:colon]
	}
	return image
}

// Allowed returns the first rule that matches the alert, or false.
func Allowed(rules []Allow, alert Alert) (Allow, bool) {
	for _, rule := range rules {
		if rule.Matches(alert) {
			return rule, true
		}
	}
	return Allow{}, false
}
