package containers

import (
	"strings"
)

// LookupCommand asks each container runtime in turn about one container,
// by its full 64-character ID, and prints the first answer as one line:
// name|image|runtime|pod namespace|pod name. It prints nothing when no
// runtime knows the container, or the ID isn't one.
func LookupCommand(id string) string {
	if !validID(id) {
		return "true"
	}
	return `{ command -v docker >/dev/null 2>&1 && docker inspect --format '{{.Name}}|{{.Config.Image}}|docker||' ` + id + ` 2>/dev/null; } || ` +
		`{ command -v podman >/dev/null 2>&1 && podman inspect --format '{{.Name}}|{{.ImageName}}|podman||' ` + id + ` 2>/dev/null; } || ` +
		`{ command -v crictl >/dev/null 2>&1 && crictl inspect -o go-template --template '{{.status.metadata.name}}|{{.status.image.image}}|cri|` +
		`{{index .status.labels "io.kubernetes.pod.namespace"}}|{{index .status.labels "io.kubernetes.pod.name"}}' ` + id + ` 2>/dev/null; } || true`
}

// Found is one container as LookupCommand describes it.
type Found struct {
	Name      string
	Image     string
	Runtime   string
	Namespace string
	Pod       string
}

// ParseLookup reads LookupCommand's output.
func ParseLookup(output []byte) (Found, bool) {
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	fields := strings.Split(line, "|")
	if len(fields) != 5 || fields[0] == "" {
		return Found{}, false
	}
	clean := func(value string) string {
		value = strings.TrimSpace(value)
		if value == noValue {
			return ""
		}
		return value
	}
	return Found{Name: strings.TrimPrefix(clean(fields[0]), "/"), Image: clean(fields[1]), Runtime: clean(fields[2]),
		Namespace: clean(fields[3]), Pod: clean(fields[4])}, true
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
