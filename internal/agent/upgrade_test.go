package agent

import (
	"strings"
	"testing"

	"deaconguard/internal/buildinfo"
)

func TestUpgradeNudge(t *testing.T) {
	previous := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = previous })
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	buildinfo.Version = "1.22.0"
	if got := upgradeNudge("1.23.0", Config{}); !strings.Contains(got, "server runs DeaconGuard 1.23.0 and this agent 1.22.0") ||
		!strings.HasSuffix(got, "DEACONGUARD_VERSION=1.23.0 sudo -E sh -") {
		t.Errorf("machine: %q", got)
	}
	if got := upgradeNudge("1.23.0", Config{Cluster: "prod"}); !strings.HasSuffix(got, "Kustomize overlay, to 1.23.0") {
		t.Errorf("cluster: %q", got)
	}
	for _, server := range []string{"1.22.0", "1.21.0", "", "dev"} {
		if got := upgradeNudge(server, Config{}); got != "" {
			t.Errorf("server %q: %q", server, got)
		}
	}
}
