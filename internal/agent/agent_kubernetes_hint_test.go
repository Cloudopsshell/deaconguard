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
	revoked := fmt.Errorf("%w (HTTP 401): the enrollment token d4f02283 was revoked on 2026-10-31 19:30 UTC. Create a new one on the Agents page", errRejected)
	if hint := kubernetesHint(revoked, true); strings.Contains(hint, "reusable") || !strings.Contains(hint, "new token") {
		t.Errorf("revoked: %q", hint)
	}
	oneTime := fmt.Errorf("%w (HTTP 401): the enrollment token d4f02283 is a one-time token, already used on 2026-10-31 19:30 UTC", errRejected)
	if hint := kubernetesHint(oneTime, true); !strings.Contains(hint, "must be reusable") {
		t.Errorf("one-time: %q", hint)
	}
	if err := removed(fmt.Errorf("%w: this agent was disconnected on 2026-10-31 19:30 UTC by admin: its enrollment token d4f02283 was revoked", errUnauthorized)); !errors.Is(err, ErrRemoved) || !strings.Contains(err.Error(), "by admin") {
		t.Errorf("disconnected: %v", err)
	}
	if err := removed(fmt.Errorf("%w: this agent is not enrolled with the server; it may have been removed", errUnauthorized)); err != ErrRemoved {
		t.Errorf("removed: %v", err)
	}
	if hint := kubernetesHint(used, false); hint != "" {
		t.Errorf("outside Kubernetes: %q", hint)
	}
}
