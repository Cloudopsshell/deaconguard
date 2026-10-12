package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
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
