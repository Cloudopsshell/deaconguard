package server

import (
	"os"
	"testing"

	"deaconguard/internal/store"
)

// The tests scan "this machine" with the Linux checks, so it is a Linux
// machine wherever they run; a Mac would only be offered the macOS checks.
func TestMain(m *testing.M) {
	store.LocalHostKind = func() string { return store.KindMachine }
	os.Exit(m.Run())
}
