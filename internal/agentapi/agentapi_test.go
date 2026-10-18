package agentapi_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/tlscert"
)

func TestTokenRoundTrip(t *testing.T) {
	token := agentapi.Token{
		ServerURL: "https://deaconguard.example.com:8443",
		Pin:       strings.Repeat("A", 43),
		Secret:    strings.Repeat("B", 43),
	}
	parsed, err := agentapi.ParseToken("  " + token.Encode() + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if parsed != token {
		t.Fatalf("got %+v", parsed)
	}
	for _, bad := range []string{
		"", "deaconguard1.", "something-else", token.Encode()[:len(token.Encode())-2],
		agentapi.Token{ServerURL: "http://insecure:8080", Pin: token.Pin, Secret: token.Secret}.Encode(),
	} {
		if _, err := agentapi.ParseToken(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestValidateServerURL(t *testing.T) {
	for _, good := range []string{"https://10.0.0.5:8443", "https://deaconguard.example.com", "https://deaconguard:8443/"} {
		if err := agentapi.ValidateServerURL(good); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{"http://10.0.0.5:8443", "https://", "https://user:pass@host", "https://host/path", "10.0.0.5:8443"} {
		if err := agentapi.ValidateServerURL(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestClientTrustsOnlyThePinnedKey(t *testing.T) {
	certificate, created, err := tlscert.Ensure(t.TempDir(), "deaconguard-test")
	if err != nil || !created {
		t.Fatalf("create certificate: %v (created %t)", err, created)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()

	get := func(pin string) error {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: agentapi.ClientTLS("127.0.0.1", pin)}}
		response, err := client.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		return err
	}
	if err := get(agentapi.PublicKeyPin(certificate.Leaf)); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := get(strings.Repeat("A", 43)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("other key accepted: %v", err)
	}
}

func TestEnsureReusesTheCertificate(t *testing.T) {
	directory := t.TempDir()
	first, _, err := tlscert.Ensure(directory, "deaconguard-test")
	if err != nil {
		t.Fatal(err)
	}
	second, created, err := tlscert.Ensure(directory, "deaconguard-test")
	if err != nil || created {
		t.Fatalf("second Ensure: %v (created %t)", err, created)
	}
	if agentapi.PublicKeyPin(first.Leaf) != agentapi.PublicKeyPin(second.Leaf) {
		t.Fatal("the key changed between starts, which would strand every agent")
	}
}

func TestSupportsYARA(t *testing.T) {
	for version, want := range map[string]bool{
		"0.5.0": true, "0.5.0-rc.1": true, "0.6.2": true, "1.0.0": true, "dev": true,
		"0.4.2": false, "0.4.0": false, "0.1.1": false, "": false,
	} {
		if got := agentapi.SupportsYARA(version); got != want {
			t.Errorf("SupportsYARA(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestSupportsLibraries(t *testing.T) {
	for version, want := range map[string]bool{
		"1.1.0": true, "1.1.0-rc.1": true, "1.2.3": true, "2.0.0": true, "dev": true,
		"1.0.2": false, "0.19.0": false, "": false,
	} {
		if got := agentapi.SupportsCheck(version, "libraries"); got != want {
			t.Errorf("agentapi.SupportsCheck(%q, libraries) = %v, want %v", version, got, want)
		}
	}
	// Checks from 0.x stay available on 1.x agents.
	if !agentapi.SupportsCheck("1.0.0", "hardening") || agentapi.SupportsCheck("0.11.0", "hardening") {
		t.Error("hardening gating changed")
	}
	err := agentapi.ErrAgentTooOld("web-01", "1.0.2", "libraries")
	if err == nil || !strings.Contains(err.Error(), "the application library check needs the DeaconGuard agent 1.1.0 or later on web-01, which runs 1.0.2") {
		t.Errorf("ErrAgentTooOld = %v", err)
	}
	if err := agentapi.ErrAgentTooOld("db-01", "0.11.0", "hardening"); !strings.Contains(err.Error(), "the hardening audit needs the DeaconGuard agent 0.12.0 or later") {
		t.Errorf("hardening message = %v", err)
	}
}
