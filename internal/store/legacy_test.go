package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpsArmorDataIsMovedToTheNewName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEACONGUARD_HOME", "")
	t.Setenv("OPSARMOR_HOME", "")
	legacy := filepath.Join(home, ".local", "share", "opsarmor")
	if err := os.MkdirAll(filepath.Join(legacy, "feeds"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"opsarmor.db", "feeds/cached.xml"} {
		if err := os.WriteFile(filepath.Join(legacy, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ListHosts(); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(home, ".local", "share", "deaconguard")
	for _, name := range []string{"deaconguard.db", "feeds/cached.xml"} {
		if _, err := os.Stat(filepath.Join(moved, name)); err != nil {
			t.Errorf("%s was not moved: %v", name, err)
		}
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("the old directory is still there: %v", err)
	}
}

func TestOpsArmorHomeIsStillHonored(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("DEACONGUARD_HOME", "")
	t.Setenv("OPSARMOR_HOME", directory)
	if err := os.WriteFile(filepath.Join(directory, "opsarmor.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if DataDir() != directory {
		t.Fatalf("DataDir() = %s, want %s", DataDir(), directory)
	}
	if _, err := ListHosts(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "deaconguard.db")); err != nil {
		t.Fatalf("database was not renamed: %v", err)
	}
}
