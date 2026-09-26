package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func withTempDataDir(t *testing.T) string {
	t.Helper()
	previous, hadPrevious := os.LookupEnv("OPSARMOR_HOME")
	directory := t.TempDir()
	if err := os.Setenv("OPSARMOR_HOME", directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv("OPSARMOR_HOME", previous)
		} else {
			_ = os.Unsetenv("OPSARMOR_HOME")
		}
	})
	return directory
}

func TestHostProfilesRoundTripWithPrivatePermissions(t *testing.T) {
	directory := withTempDataDir(t)
	keyPath := filepath.Join(directory, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("private key path placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := AddHost("ubuntu.example", "scanner", 22, &keyPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := GetHost(host.ID)
	if err != nil || !reflect.DeepEqual(got, host) {
		t.Fatalf("GetHost() = %+v, %v; want %+v", got, err, host)
	}
	info, err := os.Stat(filepath.Join(directory, "opsarmor.db"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("opsarmor.db permissions = %v, %v; want 0600", info, err)
	}
}

func TestAddHostValidatesTildeExpandedKeyPath(t *testing.T) {
	directory := withTempDataDir(t)
	home := filepath.Join(directory, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, "id_ed25519"), []byte("private key path placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := "~/id_ed25519"
	if _, err := AddHost("ubuntu.example", "scanner", 22, &keyPath); err != nil {
		t.Fatalf("AddHost rejected a valid tilde path: %v", err)
	}
}

func TestReportsSurviveHostRemoval(t *testing.T) {
	withTempDataDir(t)
	host, err := AddHost("debian.example", "scanner", 22, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := SaveReport(map[string]any{"host_id": host.ID, "finding_count": 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveHost(host.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err := GetReport(report["report_id"].(string))
	if err != nil || loaded["finding_count"] != float64(2) {
		t.Fatalf("GetReport() = %#v, %v", loaded, err)
	}
}

func TestHostKeyPinIsIdempotentAndRejectsRotation(t *testing.T) {
	withTempDataDir(t)
	host := Host{ID: "host-id", Address: "203.0.113.7", Username: "scanner", Port: 2222}
	first := "[203.0.113.7]:2222 ssh-ed25519 AAAAFIRST"
	if err := TrustHostKey(host, first); err != nil {
		t.Fatal(err)
	}
	if err := TrustHostKey(host, first); err != nil {
		t.Fatalf("re-enrolling same key: %v", err)
	}
	if err := TrustHostKey(host, "[203.0.113.7]:2222 ssh-ed25519 AAAASECOND"); err == nil {
		t.Fatal("expected changed key to be rejected")
	}
	info, err := os.Stat(KnownHostsPath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts permissions = %v, %v; want 0600", info, err)
	}
}

func TestHostKeyPinAllowsAdditionalAlgorithmButRejectsSameAlgorithmRotation(t *testing.T) {
	withTempDataDir(t)
	host := Host{ID: "host-id", Address: "203.0.113.8", Username: "scanner", Port: 22}
	if err := TrustHostKey(host, "203.0.113.8 ssh-rsa AAAARSA"); err != nil {
		t.Fatal(err)
	}
	if err := TrustHostKey(host, "203.0.113.8 ssh-ed25519 AAAAED25519"); err != nil {
		t.Fatalf("new key algorithm should be independently enrollable: %v", err)
	}
	if err := TrustHostKey(host, "203.0.113.8 ssh-ed25519 AAAACHANGED"); err == nil {
		t.Fatal("same-algorithm key rotation was silently accepted")
	}
	contents, err := os.ReadFile(KnownHostsPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), "203.0.113.8 ") != 2 {
		t.Fatalf("expected both algorithm pins, got %q", contents)
	}
}
