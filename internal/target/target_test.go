package target

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeTarget struct{ answers map[string]string }

func (f *fakeTarget) Run(command string, _ []byte, _ int, _ time.Duration) ([]byte, error) {
	if answer, ok := f.answers[command]; ok {
		return []byte(answer), nil
	}
	return nil, errors.New("unexpected command " + command)
}
func (f *fakeTarget) Observe(CommandObserver) {}
func (f *fakeTarget) Close() error            { return nil }

func TestCollectInventoryOnUbuntu(t *testing.T) {
	osRelease, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "rootfs", "etc", "os-release"))
	if err != nil {
		t.Fatal(err)
	}
	machine := &fakeTarget{answers: map[string]string{
		"cat /etc/os-release":                   string(osRelease),
		"head -c 33554433 /var/lib/dpkg/status": "Package: bash\nStatus: install ok installed\nVersion: 5.2\n",
		"uname -r":                              "6.8.0-45-generic\n",
	}}
	inventory, err := CollectInventory(machine)
	if err != nil || inventory.Kernel != "6.8.0-45-generic" || inventory.DPKGStatus == "" || inventory.RPMQuery != "" {
		t.Fatalf("inventory = %+v, err = %v", inventory, err)
	}
}

type exitError struct{}

func (exitError) Error() string   { return "exit" }
func (exitError) ExitStatus() int { return 2 }

func TestExitStatus(t *testing.T) {
	if status, ok := ExitStatus(errors.Join(errors.New("wrapped"), exitError{})); !ok || status != 2 {
		t.Fatalf("ExitStatus = %d, %v", status, ok)
	}
	if _, ok := ExitStatus(errors.New("timed out")); ok {
		t.Fatal("a plain error has no exit status")
	}
}
