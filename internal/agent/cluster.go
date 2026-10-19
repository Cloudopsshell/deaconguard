package agent

import (
	"context"
	"fmt"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/checks"
	"deaconguard/internal/kube"
	"deaconguard/internal/scan"
)

// connectCluster reaches the API of the cluster the agent runs in; tests
// replace it.
var connectCluster = func() (*kube.Client, error) { return kube.Connect("", "") }

// scanCluster runs a cluster agent's job: the Kubernetes check, read-only,
// with the pod's service account. The server adds the version's support
// and CVEs, so the agent needs to reach only the API and the server.
func scanCluster(ctx context.Context, config Config, job agentapi.Job, emit func(scan.Event)) (map[string]any, error) {
	for _, id := range job.Checks {
		if id != checks.Kubernetes {
			return nil, fmt.Errorf("a cluster agent runs only the Kubernetes check, not %q", id)
		}
	}
	client, err := connectCluster()
	if err != nil {
		return nil, fmt.Errorf("reach the Kubernetes API: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	return scan.RunCluster(ctx, client, config.Cluster, config.HostID, emit)
}
