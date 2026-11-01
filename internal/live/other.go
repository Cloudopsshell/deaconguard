//go:build !linux

package live

import "time"

// ErrUnsupported explains why this machine can't run live detection.
type ErrUnsupported struct{ Reason string }

func (err ErrUnsupported) Error() string { return err.Reason }

// Counters are the watchers' running totals since they started.
type Counters struct {
	Execs, Writes, Lost uint64
}

type watcher struct{}

func (w *watcher) poll(int, func(Event)) error { return nil }
func (w *watcher) counters() (Counters, error) { return Counters{}, nil }
func (w *watcher) close()                      {}

func startWatcher(string) (*watcher, error) {
	return nil, ErrUnsupported{"live detection runs on Linux only"}
}

// KernelRelease is the running kernel's version; not Linux, so none.
func KernelRelease() string { return "" }

func selfUsage() (time.Duration, uint64) { return 0, 0 }

type noMachine struct{}

func (noMachine) Executable(uint32) string       { return "" }
func (noMachine) HasTerminal(uint32) bool        { return false }
func (noMachine) Ancestors(uint32) []string      { return nil }
func (noMachine) WorkingDirectory(uint32) string { return "" }
func (noMachine) User(uint32) string             { return "" }

func newMachine(string) Machine { return noMachine{} }

func runTestProgram(string) error { return ErrUnsupported{"live detection runs on Linux only"} }
