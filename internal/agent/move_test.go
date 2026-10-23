package agent

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/tlscert"
)

// agentServer answers the agent API on its own port, with the certificate
// of shared, as one DeaconGuard server does on its two ports.
func agentServer(t *testing.T, shared *httptest.Server, hello int) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == agentapi.PathPrefix+agentapi.PathHello && r.Header.Get("Authorization") == "Bearer host.secret" {
			w.WriteHeader(hello)
			return
		}
		http.NotFound(w, r)
	}))
	if shared != nil {
		server.TLS = shared.TLS.Clone()
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func portOf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	parsed, _ := url.Parse(server.URL)
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestAgentMovesToTheAgentPort(t *testing.T) {
	dashboard := agentServer(t, nil, http.StatusNoContent)
	agents := agentServer(t, dashboard, http.StatusNoContent)
	pin := agentapi.PublicKeyPin(dashboard.Certificate())
	config := Config{ServerURL: dashboard.URL, Pin: pin, HostID: "host", Credential: "secret"}
	path := filepath.Join(t.TempDir(), "agent.json")

	moved, client, err := moveToPort(context.Background(), config, portOf(t, agents), path)
	if err != nil || client == nil {
		t.Fatalf("move: %v", err)
	}
	if moved.ServerURL != agents.URL || moved.Pin != pin || moved.Credential != "secret" {
		t.Fatalf("moved config = %+v", moved)
	}
	saved, err := LoadConfig(path)
	if err != nil || saved.ServerURL != agents.URL {
		t.Fatalf("saved config = %+v, %v", saved, err)
	}
}

func TestAgentStaysWhenTheAgentPortIsWrong(t *testing.T) {
	dashboard := agentServer(t, nil, http.StatusNoContent)
	pin := agentapi.PublicKeyPin(dashboard.Certificate())
	config := Config{ServerURL: dashboard.URL, Pin: pin, HostID: "host", Credential: "secret"}
	path := filepath.Join(t.TempDir(), "agent.json")

	// Another server, with another key, must not be trusted.
	certificate, _, err := tlscert.Ensure(t.TempDir(), "impostor")
	if err != nil {
		t.Fatal(err)
	}
	impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	impostor.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	impostor.StartTLS()
	defer impostor.Close()
	// A port that refuses the agent, or isn't a port at all.
	refusing := agentServer(t, dashboard, http.StatusUnauthorized)
	for _, port := range []string{portOf(t, impostor), portOf(t, refusing), "0", "http"} {
		if _, _, err := moveToPort(context.Background(), config, port, path); err == nil {
			t.Errorf("moved to port %s", port)
		}
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a failed move saved a config")
	}
}

// An agent that moved goes back to where it came from when the agent port is
// turned off, and remembers that address only while it is on the agent port.
func TestAgentMovesBackWhenTheAgentPortGoes(t *testing.T) {
	dashboard := agentServer(t, nil, http.StatusNoContent)
	agents := agentServer(t, dashboard, http.StatusNoContent)
	pin := agentapi.PublicKeyPin(dashboard.Certificate())
	config := Config{ServerURL: dashboard.URL, Pin: pin, HostID: "host", Credential: "secret"}
	path := filepath.Join(t.TempDir(), "agent.json")

	moved, _, err := moveToPort(context.Background(), config, portOf(t, agents), path)
	if err != nil || moved.MovedFrom != dashboard.URL {
		t.Fatalf("moved = %+v, %v", moved, err)
	}
	agents.Close()
	back, client, err := moveBack(context.Background(), moved, path)
	if err != nil || client == nil || back.ServerURL != dashboard.URL || back.MovedFrom != "" {
		t.Fatalf("back = %+v, %v", back, err)
	}
	if saved, err := LoadConfig(path); err != nil || saved.ServerURL != dashboard.URL || saved.MovedFrom != "" {
		t.Fatalf("saved = %+v, %v", saved, err)
	}

	// Nowhere to go back to: the dashboard's port is gone too.
	dashboard.Close()
	if _, _, err := moveBack(context.Background(), moved, path); err == nil {
		t.Fatal("moved back to a closed port")
	}
}

func TestReturnTo(t *testing.T) {
	for config, want := range map[Config]string{
		{ServerURL: "https://dg:8444", MovedFrom: "https://dg.example:9443"}: "https://dg.example:9443",
		{ServerURL: "https://dg:8444"}:                                       "https://dg:8443",
		{ServerURL: "https://dg:8443"}:                                       "",
		{ServerURL: "https://dg"}:                                            "",
	} {
		if got := returnTo(config); got != want {
			t.Errorf("returnTo(%+v) = %q, want %q", config, got, want)
		}
	}
}
