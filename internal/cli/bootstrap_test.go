package cli

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
	"deaconguard/internal/tlscert"
)

func TestBootstrapAdminFromFile(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	secret := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(secret, []byte("Correct-Horse-9-battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEACONGUARD_ADMIN_USER", "admin")
	t.Setenv("DEACONGUARD_ADMIN_PASSWORD_FILE", secret)
	if err := bootstrapAdmin(io.Discard); err != nil {
		t.Fatal(err)
	}
	users, err := store.ListUsers()
	if err != nil || len(users) != 1 || users[0].Username != "admin" || users[0].Role != store.RoleAdmin {
		t.Fatalf("users = %+v, %v", users, err)
	}
	if _, err := store.Authenticate("admin", []byte("Correct-Horse-9-battery")); err != nil {
		t.Fatalf("sign in with the file's password, without its newline: %v", err)
	}

	// Once an account exists, the environment changes nothing.
	if err := os.WriteFile(secret, []byte("Another-Horse-9-battery"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEACONGUARD_ADMIN_USER", "second")
	if err := bootstrapAdmin(io.Discard); err != nil {
		t.Fatal(err)
	}
	if users, _ := store.ListUsers(); len(users) != 1 {
		t.Fatalf("a second account was created: %+v", users)
	}
}

func TestBootstrapAdminNeedsPassword(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	t.Setenv("DEACONGUARD_ADMIN_USER", "admin")
	t.Setenv("DEACONGUARD_ADMIN_PASSWORD_FILE", "")
	t.Setenv("DEACONGUARD_ADMIN_PASSWORD", "")
	if err := bootstrapAdmin(io.Discard); err == nil || !strings.Contains(err.Error(), "without") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("DEACONGUARD_ADMIN_USER", "")
	if err := bootstrapAdmin(io.Discard); err != nil {
		t.Fatalf("no user set: %v", err)
	}
}

// A secret that doesn't exist yet makes the server wait for it, serving a
// page that says so and answers health checks, rather than exit.
func TestServerWaitsForTheFirstAccountsPassword(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	secret := filepath.Join(t.TempDir(), "password")
	t.Setenv("DEACONGUARD_ADMIN_USER", "admin")
	t.Setenv("DEACONGUARD_ADMIN_PASSWORD_FILE", secret)
	t.Setenv("DEACONGUARD_ADMIN_SECRET", "deaconguard-admin")
	t.Setenv("DEACONGUARD_NAMESPACE", "deaconguard")
	if err := bootstrapAdmin(io.Discard); !errors.Is(err, errAdminPasswordMissing) {
		t.Fatalf("a missing file must mean waiting: %v", err)
	}
	certificate, _, err := tlscert.Ensure(t.TempDir(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	address := listener.Addr().String()
	listener.Close()
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- waitForAdmin(address, certificate, &output) }()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	var version, page *http.Response
	for range 50 {
		if version, err = client.Get("https://" + address + "/api/version"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || version.StatusCode != http.StatusOK {
		t.Fatalf("health check while waiting: %v %v", version, err)
	}
	if page, err = client.Get("https://" + address + "/"); err != nil || page.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("page while waiting: %v %v", page, err)
	}
	body, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(body), "kubectl -n deaconguard create secret generic deaconguard-admin --from-literal=password=") {
		t.Errorf("the page should say how to create the secret: %s", body)
	}

	if err := os.WriteFile(secret, []byte("Correct-Horse-9-battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the server didn't notice the password")
	}
	if users, _ := store.ListUsers(); len(users) != 1 || !strings.Contains(output.String(), "Created the first account, admin") {
		t.Fatalf("users = %+v, output %q", users, output.String())
	}
}

func TestAgentWithoutTokenSaysWhereToPutIt(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("DEACONGUARD_ENROLL_TOKEN", "")
	t.Setenv("DEACONGUARD_ENROLL_TOKEN_FILE", filepath.Join(directory, "token"))
	_, err := loadOrEnroll(t.Context(), filepath.Join(directory, "agent.json"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(directory, "token")) {
		t.Fatalf("err = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "token"), []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if token := enrollToken(); token != "" {
		t.Fatalf("blank token file: %q", token)
	}
}

func TestAgentKeepsItsEnrollmentWhenTheTokenCantReplaceIt(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.json")
	saved := `{"server_url":"https://old.example:8444","pin":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","host_id":"h1","credential":"c1"}`
	if err := os.WriteFile(path, []byte(saved), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEACONGUARD_ENROLL_TOKEN_FILE", "")
	// Same certificate: nothing to do.
	t.Setenv("DEACONGUARD_ENROLL_TOKEN", agentapi.Token{ServerURL: "https://old.example:8443", Pin: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Secret: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}.Encode())
	var log strings.Builder
	config, err := loadOrEnroll(t.Context(), path, &log)
	if err != nil || config.HostID != "h1" || log.Len() != 0 {
		t.Fatalf("same server: %+v, %v, %q", config, err, log.String())
	}
	// Another certificate, from a server that can't be reached: the agent
	// says so and keeps what it has.
	t.Setenv("DEACONGUARD_ENROLL_TOKEN", agentapi.Token{ServerURL: "https://127.0.0.1:1", Pin: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Secret: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"}.Encode())
	config, err = loadOrEnroll(t.Context(), path, &log)
	if err != nil || config.HostID != "h1" || !strings.Contains(log.String(), "keeping the enrollment") {
		t.Fatalf("unreachable new server: %+v, %v, %q", config, err, log.String())
	}
}
