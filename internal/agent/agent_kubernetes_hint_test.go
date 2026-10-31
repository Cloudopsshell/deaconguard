package agent

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestKubernetesHint(t *testing.T) {
	used := fmt.Errorf("%w (HTTP 401): the enrollment token is invalid, expired, revoked, or already used", errRejected)
	timeout := errors.New(`Post "https://dashboard.example.com:8444/agent/v1/enroll": dial tcp 203.0.113.1:8444: i/o timeout`)
	refused := fmt.Errorf("%w (HTTP 400): the agent reported an invalid hostname", errRejected)
	if hint := kubernetesHint(used, true); !strings.Contains(hint, "must be reusable") || !strings.Contains(hint, "Enroll a machine > Kubernetes") {
		t.Errorf("already used: %q", hint)
	}
	if hint := kubernetesHint(timeout, true); !strings.Contains(hint, "https://deaconguard.deaconguard.svc:8444") {
		t.Errorf("unreachable: %q", hint)
	}
	if hint := kubernetesHint(refused, true); hint != "" {
		t.Errorf("another refusal: %q", hint)
	}
	if hint := kubernetesHint(used, false); hint != "" {
		t.Errorf("outside Kubernetes: %q", hint)
	}
}
