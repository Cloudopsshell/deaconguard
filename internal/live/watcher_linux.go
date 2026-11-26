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
	events   events
	cpus     int
	// compat is whether the watchers for kernels before 5.8 run.
	compat bool
}

// Counters are the watchers' running totals since they started.
type Counters struct {
	Execs, Writes, Connects, Calls, Lost uint64
}

// minimumKernel is the first kernel with everything the watchers for
// older kernels use: the cgroup of an event above all. Kernels from 5.8,
// and older ones with the ring buffer, run the watchers made for 5.8.
var minimumKernel = [2]int{4, 18}

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
	return releaseAtLeast(release, minimumKernel[0], minimumKernel[1])
}

// releaseAtLeast reports whether a kernel release, such as
// "5.4.0-216-generic", is major.minor or later.
func releaseAtLeast(release string, major, minor int) bool {
	var gotMajor, gotMinor int
	if _, err := fmt.Sscanf(release, "%d.%d", &gotMajor, &gotMinor); err != nil {
		return false
	}
	return gotMajor > major || gotMajor == major && gotMinor >= minor
}

// kernelAtLeast reports whether the running kernel is major.minor or later.
func kernelAtLeast(major, minor int) bool {
	return releaseAtLeast(KernelRelease(), major, minor)
}

// ErrUnsupported explains why this machine can't run live detection.
type ErrUnsupported struct{ Reason string }

func (err ErrUnsupported) Error() string { return err.Reason }

// unsupportedReason says why this machine can't run live detection, as
// far as can be told without trying, or "".
func unsupportedReason() string {
	release := KernelRelease()
	if !supportedKernel(release) {
		return fmt.Sprintf("Linux %s is older than %d.%d, the first version live detection works on", release, minimumKernel[0], minimumKernel[1])
	}
	return ""
}

// startWatcher loads the watchers into the kernel and attaches them.
func startWatcher(hostRoot string) (*watcher, error) {
	if reason := unsupportedReason(); reason != "" {
		return nil, ErrUnsupported{reason}
	}
	raiseLockedMemory()
	compat := !ringbufSupported()
	source := watchObject
	if compat {
		source = compatObject
	}
	object, err := ParseObject(source)
	if err != nil {
		return nil, err
	}
	cpus, err := possibleCPUs()
	if err != nil {
		return nil, fmt.Errorf("count the CPUs: %w", err)
	}
	w := &watcher{maps: map[string]int{}, cpus: cpus, compat: compat}
	fail := func(err error) (*watcher, error) {
		w.close()
		// The kernel's checker refuses a watcher with EACCES too, with its
		// log ("processed N insns"): that's not a question of rights.
		if (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) && !strings.Contains(err.Error(), " insns ") {
			// BPF and PERFMON came with Linux 5.8; before, loading takes
			// SYS_ADMIN, and SYS_RESOURCE to lift the locked-memory limit.
			rights := "the BPF and PERFMON capabilities"
			if !kernelAtLeast(5, 8) {
				rights = "on this kernel, older than 5.8, the SYS_ADMIN and SYS_RESOURCE capabilities"
			}
			return nil, ErrUnsupported{"the agent isn't allowed to load programs into the kernel: it needs root, or " + rights + " (" + err.Error() + ")"}
		}
		return nil, err
	}
	var ringSize uint32
	for _, spec := range object.Maps {
		if spec.Type == mapTypePerfEventArray {
			spec.MaxEntries = uint32(cpus)
		}
		fd, err := createMap(spec)
		if err != nil {
			return fail(err)
		}
		w.maps[spec.Name] = fd
		if spec.Type == mapTypeRingbuf {
			ringSize = spec.MaxEntries
		}
	}
	root, err := tracefs(hostRoot)
	if err != nil {
		return fail(ErrUnsupported{err.Error()})
	}
	if err := w.configure(root); err != nil {
		return fail(err)
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
	if compat {
		buffers, err := openPerfBuffers(w.maps["events"], cpus)
		if err != nil {
			return fail(err)
		}
		w.events = buffers
	} else {
		ring, err := openRing(w.maps["events"], ringSize)
		if err != nil {
			return fail(err)
		}
		w.events = ring
	}
	return w, nil
}

// configure tells the watchers which paths, programs and ports to report,
// which process is the agent, and how to read a new process's ID.
func (w *watcher) configure(tracefsRoot string) error {
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
	for index, folder := range execMarkedFolders {
		if err := put("exec_paths", index, watchedPathValue(folder, "")); err != nil {
			return err
		}
	}
	index := 0
	for shell := range shells {
		if err := put("connect_comms", index, watchedNameValue(shell)); err != nil {
			return err
		}
		index++
	}
	one := []byte{1, 0, 0, 0}
	for port := range poolPorts {
		if err := put("watched_ports", int(port), one); err != nil {
			return err
		}
	}
	settings := make([]byte, 4)
	binary.LittleEndian.PutUint32(settings, forkChildOffset(tracefsRoot))
	if err := put("settings", 0, settings); err != nil {
		return err
	}
	self := make([]byte, 4)
	binary.LittleEndian.PutUint32(self, uint32(os.Getpid()))
	return put("self", 0, self)
}

// forkChildOffset reads where sched_process_fork keeps the new process's
// ID: 44 in older kernels, 20 since the names moved out of the record. Any
// other layout returns 0, and the watchers don't follow forks.
func forkChildOffset(tracefsRoot string) uint32 {
	format, err := os.ReadFile(tracefsRoot + "/events/sched/sched_process_fork/format")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(format), "\n") {
		if !strings.Contains(line, " child_pid;") {
			continue
		}
		_, after, ok := strings.Cut(line, "offset:")
		if !ok {
			return 0
		}
		offset, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(after, ";", 2)[0]))
		if err == nil && (offset == 20 || offset == 44) {
			return uint32(offset)
		}
	}
	return 0
}

// poll waits up to timeoutMS for events and hands each to handle.
func (w *watcher) poll(timeoutMS int, handle func(Event)) error {
	if err := w.events.wait(timeoutMS); err != nil {
		return err
	}
	w.events.read(func(raw []byte) {
		if event, err := ParseEvent(raw); err == nil {
			handle(event)
		}
	})
	return nil
}

// mark marks a process as the watchers mark a program started from a
// temporary folder.
func (w *watcher) mark(pid uint32) {
	key, value := make([]byte, 4), make([]byte, 4)
	binary.LittleEndian.PutUint32(key, pid)
	binary.LittleEndian.PutUint32(value, WhyMarked)
	updateMap(w.maps["marked"], key, value)
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
	if counters.Connects, err = read(3); err != nil {
		return counters, err
	}
	if counters.Calls, err = read(4); err != nil {
		return counters, err
	}
	counters.Lost, err = read(2)
	return counters, err
}

// close detaches and unloads the watchers; the kernel removes them once
// their last file descriptor is closed.
func (w *watcher) close() {
	if w.events != nil {
		w.events.close()
		w.events = nil
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
