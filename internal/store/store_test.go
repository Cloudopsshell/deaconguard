package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func withTempDataDir(t *testing.T) string {
	t.Helper()
	previous, hadPrevious := os.LookupEnv("DEACONGUARD_HOME")
	directory := t.TempDir()
	if err := os.Setenv("DEACONGUARD_HOME", directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv("DEACONGUARD_HOME", previous)
		} else {
			_ = os.Unsetenv("DEACONGUARD_HOME")
		}
	})
	return directory
}

// addTestHost inserts a host directly, so tests can add several.
func addTestHost(t *testing.T, address, transport string) Host {
	t.Helper()
	db, err := database()
	if err != nil {
		t.Fatal(err)
	}
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	host := Host{ID: id, Address: address, Username: "scanner", Transport: transport}
	if err := insertHost(db, host); err != nil {
		t.Fatal(err)
	}
	return host
}

func TestLocalHostRoundTripWithPrivatePermissions(t *testing.T) {
	directory := withTempDataDir(t)
	host, err := AddLocalHost("build-01", "ops")
	if err != nil {
		t.Fatal(err)
	}
	got, err := GetHost(host.ID)
	if err != nil || !reflect.DeepEqual(got, host) {
		t.Fatalf("GetHost() = %+v, %v; want %+v", got, err, host)
	}
	if _, err := AddLocalHost("build-01", "ops"); !errors.Is(err, ErrLocalHostExists) {
		t.Fatalf("a second local host: %v", err)
	}
	info, err := os.Stat(filepath.Join(directory, "deaconguard.db"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("deaconguard.db permissions = %v, %v; want 0600", info, err)
	}
}

func TestReportsSurviveHostRemoval(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "debian.example", TransportLocal)
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
