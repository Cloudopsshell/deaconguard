package containers

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	id := strings.Repeat("9e", 32)
	if command := LookupCommand(id); !strings.Contains(command, id) || !strings.Contains(command, "crictl inspect") {
		t.Fatalf("command: %s", command)
	}
	if command := LookupCommand("abc; rm -rf /"); command != "true" {
		t.Fatalf("an ID that isn't one: %s", command)
	}
	for output, want := range map[string]Found{
		"/web|nginx:1.27|docker||\n":                 {Name: "web", Image: "nginx:1.27", Runtime: "docker"},
		"api|ghcr.io/acme/api:2|cri|shop|api-7d9f\n": {Name: "api", Image: "ghcr.io/acme/api:2", Runtime: "cri", Namespace: "shop", Pod: "api-7d9f"},
		"api|x|cri|<no value>|<no value>":            {Name: "api", Image: "x", Runtime: "cri"},
	} {
		if got, ok := ParseLookup([]byte(output)); !ok || got != want {
			t.Errorf("%q: %+v %v", output, got, ok)
		}
	}
	for _, output := range []string{"", "\n", "a|b|c"} {
		if _, ok := ParseLookup([]byte(output)); ok {
			t.Errorf("%q: found", output)
		}
	}
}
