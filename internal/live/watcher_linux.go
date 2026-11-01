//go:build linux

package live

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// watcher is the watchers, loaded and attached.
type watcher struct {
	maps     map[string]int
	programs []int
	links    []int
	ring     *ring
	cpus     int
}

// Counters are the watchers' running totals since they started.
type Counters struct {
	Execs, Writes, Lost uint64
}

// minimumKernel is the first kernel with everything the watchers use,
// the ring buffer above all.
var minimumKernel = [2]int{5, 8}

// KernelRelease is the running kernel's version, such as "6.8.0-45-generic".
func KernelRelease() string {
	var name unix.Utsname
	if unix.Uname(&name) != nil {
		return ""
	}
	return unix.ByteSliceToString(name.Release[:])
}

// supportedKernel reports whether release is minimumKernel or later.
func supportedKernel(release string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > minimumKernel[0] || major == minimumKernel[0] && minor >= minimumKernel[1]
}

// ErrUnsupported explains why this machine can't run live detection.
type ErrUnsupported struct{ Reason string }

func (err ErrUnsupported) Error() string { return err.Reason }

// startWatcher loads the watchers into the kernel and attaches them.
func startWatcher(hostRoot string) (*watcher, error) {
	release := KernelRelease()
	if !supportedKernel(release) {
		return nil, ErrUnsupported{fmt.Sprintf("Linux %s is older than %d.%d, the first version live detection works on", release, minimumKernel[0], minimumKernel[1])}
	}
	object, err := ParseObject(watchObject)
	if err != nil {
		return nil, err
	}
	cpus, err := possibleCPUs()
	if err != nil {
		return nil, fmt.Errorf("count the CPUs: %w", err)
	}
	w := &watcher{maps: map[string]int{}, cpus: cpus}
	fail := func(err error) (*watcher, error) {
		w.close()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, ErrUnsupported{"the agent isn't allowed to load programs into the kernel: it needs root, or the BPF and PERFMON capabilities (" + err.Error() + ")"}
		}
		return nil, err
	}
	var ringSize uint32
	for _, spec := range object.Maps {
		fd, err := createMap(spec)
		if err != nil {
			return fail(err)
		}
		w.maps[spec.Name] = fd
		if spec.Type == mapTypeRingbuf {
			ringSize = spec.MaxEntries
		}
	}
	if err := w.configure(); err != nil {
		return fail(err)
	}
	root, err := tracefs(hostRoot)
	if err != nil {
		return fail(ErrUnsupported{err.Error()})
	}
	attached := map[string]bool{}
	for _, program := range object.Programs {
		instructions, err := program.Linked(w.maps)
		if err != nil {
			return fail(err)
		}
		fd, err := loadProgram(program.Event, instructions, object.License)
		if err != nil {
			return fail(err)
		}
		w.programs = append(w.programs, fd)
		link, ok, err := attach(root, program.Category, program.Event, fd)
		if err != nil {
			return fail(err)
		}
		if ok {
			w.links = append(w.links, link)
			attached[program.Event] = true
		}
	}
	// Without these, programs that start or files that change would go
	// unseen; the others are the older forms some architectures lack.
	for _, required := range []string{"sched_process_exec", "sys_enter_execve", "sys_enter_openat"} {
		if !attached[required] {
			return fail(ErrUnsupported{"the kernel has no " + required + " tracepoint"})
		}
	}
	if w.ring, err = openRing(w.maps["events"], ringSize); err != nil {
		return fail(err)
	}
	return w, nil
}

// configure tells the watchers which paths to report and which process is
// the agent.
func (w *watcher) configure() error {
	key := make([]byte, 4)
	put := func(mapName string, index int, value []byte) error {
		binary.LittleEndian.PutUint32(key, uint32(index))
		if err := updateMap(w.maps[mapName], key, value); err != nil {
			return fmt.Errorf("configure %s: %w", mapName, err)
		}
		return nil
	}
	for index, prefix := range watchedPrefixes {
		if err := put("watched_paths", index, watchedPathValue(prefix, "")); err != nil {
			return err
		}
	}
	if err := put("watched_paths", len(watchedPrefixes), watchedPathValue(homeSSHPrefix, homeSSHAfter)); err != nil {
		return err
	}
	for index, name := range watchedNames {
		if err := put("watched_names", index, watchedNameValue(name)); err != nil {
			return err
		}
	}
	self := make([]byte, 4)
	binary.LittleEndian.PutUint32(self, uint32(os.Getpid()))
	return put("self", 0, self)
}

// poll waits up to timeoutMS for events and hands each to handle.
func (w *watcher) poll(timeoutMS int, handle func(Event)) error {
	if err := w.ring.wait(timeoutMS); err != nil {
		return err
	}
	w.ring.read(func(raw []byte) {
		if event, err := ParseEvent(raw); err == nil {
			handle(event)
		}
	})
	return nil
}

// counters sums the watchers' per-CPU counters.
func (w *watcher) counters() (Counters, error) {
	key := make([]byte, 4)
	value := make([]byte, 8*w.cpus)
	read := func(index uint32) (uint64, error) {
		binary.LittleEndian.PutUint32(key, index)
		if err := lookupMap(w.maps["counters"], key, value); err != nil {
			return 0, err
		}
		var total uint64
		for cpu := 0; cpu < w.cpus; cpu++ {
			total += binary.LittleEndian.Uint64(value[8*cpu:])
		}
		return total, nil
	}
	var counters Counters
	var err error
	if counters.Execs, err = read(0); err != nil {
		return counters, err
	}
	if counters.Writes, err = read(1); err != nil {
		return counters, err
	}
	counters.Lost, err = read(2)
	return counters, err
}

// close detaches and unloads the watchers; the kernel removes them once
// their last file descriptor is closed.
func (w *watcher) close() {
	if w.ring != nil {
		w.ring.close()
	}
	for _, fd := range w.links {
		unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		unix.Close(fd)
	}
	for _, fd := range w.programs {
		unix.Close(fd)
	}
	for _, fd := range w.maps {
		unix.Close(fd)
	}
	w.links, w.programs, w.maps = nil, nil, map[string]int{}
}

// procStat reads /proc/PID/stat's fields after the process name, which may
// itself hold spaces and parentheses.
func procStat(pid int) []string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil
	}
	text := string(raw)
	end := strings.LastIndexByte(text, ')')
	if end < 0 {
		return nil
	}
	return strings.Fields(text[end+1:])
}
