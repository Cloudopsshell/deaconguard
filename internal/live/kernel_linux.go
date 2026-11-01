//go:build linux

package live

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The bpf() commands the loader uses, from the kernel's enum bpf_cmd.
const (
	cmdMapCreate     = 0
	cmdMapLookupElem = 1
	cmdMapUpdateElem = 2
	cmdProgLoad      = 5
)

// progTypeTracepoint is BPF_PROG_TYPE_TRACEPOINT.
const progTypeTracepoint = 5

// mapTypeRingbuf is BPF_MAP_TYPE_RINGBUF.
const mapTypeRingbuf = 27

// attrSize is how much of union bpf_attr the loader fills; the kernel
// accepts a shorter or longer union as long as the rest is zero.
const attrSize = 128

func bpf(cmd int, attr []byte) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func pointer(data []byte) uint64 {
	if len(data) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&data[0])))
}

// kernelName is a map's or program's name as the kernel shows it, in
// bpftool and /proc: at most 15 letters, digits and underscores.
func kernelName(name string) []byte {
	clean := []byte{}
	for _, c := range []byte("dg_" + name) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			clean = append(clean, c)
		}
	}
	if len(clean) > 15 {
		clean = clean[:15]
	}
	return clean
}

func createMap(spec MapSpec) (int, error) {
	attr := make([]byte, attrSize)
	little := binary.LittleEndian
	little.PutUint32(attr[0:], spec.Type)
	little.PutUint32(attr[4:], spec.KeySize)
	little.PutUint32(attr[8:], spec.ValueSize)
	little.PutUint32(attr[12:], spec.MaxEntries)
	little.PutUint32(attr[16:], spec.Flags)
	copy(attr[28:44], kernelName(spec.Name))
	fd, err := bpf(cmdMapCreate, attr)
	if err != nil {
		return -1, fmt.Errorf("create map %s: %w", spec.Name, err)
	}
	return fd, nil
}

func updateMap(fd int, key, value []byte) error {
	attr := make([]byte, attrSize)
	little := binary.LittleEndian
	little.PutUint32(attr[0:], uint32(fd))
	little.PutUint64(attr[8:], pointer(key))
	little.PutUint64(attr[16:], pointer(value))
	_, err := bpf(cmdMapUpdateElem, attr)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

func lookupMap(fd int, key, value []byte) error {
	attr := make([]byte, attrSize)
	little := binary.LittleEndian
	little.PutUint32(attr[0:], uint32(fd))
	little.PutUint64(attr[8:], pointer(key))
	little.PutUint64(attr[16:], pointer(value))
	_, err := bpf(cmdMapLookupElem, attr)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// loadProgram hands one watcher to the kernel, which checks it before
// accepting it. On refusal it loads it again with the checker's log, so the
// error says why.
func loadProgram(name string, instructions []byte, license string) (int, error) {
	licenseBytes := append([]byte(license), 0)
	load := func(log []byte) (int, error) {
		attr := make([]byte, attrSize)
		little := binary.LittleEndian
		little.PutUint32(attr[0:], progTypeTracepoint)
		little.PutUint32(attr[4:], uint32(len(instructions)/instructionSize))
		little.PutUint64(attr[8:], pointer(instructions))
		little.PutUint64(attr[16:], pointer(licenseBytes))
		if log != nil {
			little.PutUint32(attr[24:], 1)
			little.PutUint32(attr[28:], uint32(len(log)))
			little.PutUint64(attr[32:], pointer(log))
		}
		copy(attr[48:64], kernelName(name))
		fd, err := bpf(cmdProgLoad, attr)
		runtime.KeepAlive(instructions)
		runtime.KeepAlive(licenseBytes)
		runtime.KeepAlive(log)
		return fd, err
	}
	fd, err := load(nil)
	if err == nil {
		return fd, nil
	}
	log := make([]byte, 1<<20)
	if _, retry := load(log); retry == nil {
		return -1, fmt.Errorf("load %s: %w", name, err)
	}
	lines := strings.Split(strings.TrimSpace(cString(log)), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return -1, fmt.Errorf("load %s: %w: %s", name, err, strings.Join(lines, " / "))
}

// tracefsRoots are where the kernel's tracing file system may be mounted:
// on the machine, or under the node's root for an agent in Kubernetes.
func tracefsRoots(hostRoot string) []string {
	roots := []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}
	if hostRoot != "" && hostRoot != "/" {
		roots = append(roots, filepath.Join(hostRoot, "sys/kernel/tracing"), filepath.Join(hostRoot, "sys/kernel/debug/tracing"))
	}
	return roots
}

// tracefs finds the tracing file system, mounting it at
// /sys/kernel/tracing when nothing has, as systemd does at boot.
func tracefs(hostRoot string) (string, error) {
	for _, root := range tracefsRoots(hostRoot) {
		if _, err := os.Stat(filepath.Join(root, "events/sched/sched_process_exec/id")); err == nil {
			return root, nil
		}
	}
	if err := unix.Mount("tracefs", "/sys/kernel/tracing", "tracefs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err == nil {
		if _, err := os.Stat("/sys/kernel/tracing/events/sched/sched_process_exec/id"); err == nil {
			return "/sys/kernel/tracing", nil
		}
	}
	return "", errors.New("the kernel's tracing file system (tracefs) isn't available")
}

// attach connects a loaded watcher to its tracepoint. ok is false when the
// kernel has no such tracepoint, as for open() on arm64.
func attach(root, category, event string, program int) (fd int, ok bool, err error) {
	raw, err := os.ReadFile(filepath.Join(root, "events", category, event, "id"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return -1, false, nil
		}
		return -1, false, err
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return -1, false, fmt.Errorf("read the id of %s/%s: %w", category, event, err)
	}
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      id,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err = unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, false, fmt.Errorf("open %s/%s: %w", category, event, err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, program); err != nil {
		unix.Close(fd)
		return -1, false, fmt.Errorf("attach to %s/%s: %w", category, event, err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(fd)
		return -1, false, fmt.Errorf("enable %s/%s: %w", category, event, err)
	}
	return fd, true, nil
}

// possibleCPUs counts the CPUs a per-CPU map keeps a value for.
func possibleCPUs() (int, error) {
	raw, err := os.ReadFile("/sys/devices/system/cpu/possible")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, part := range strings.Split(strings.TrimSpace(string(raw)), ",") {
		first, last, isRange := strings.Cut(part, "-")
		low, err := strconv.Atoi(first)
		if err != nil {
			return 0, err
		}
		high := low
		if isRange {
			if high, err = strconv.Atoi(last); err != nil {
				return 0, err
			}
		}
		count += high - low + 1
	}
	return count, nil
}

// ring reads the watchers' ring buffer: a consumer page the agent writes
// its position to, a producer page the kernel writes its position to, and
// the data, which the kernel maps twice in a row so a record that wraps
// around reads as one piece.
type ring struct {
	fd       int
	consumer []byte
	producer []byte
	data     []byte
	mask     uint64
	epoll    int
}

const (
	ringBusy    = 1 << 31
	ringDiscard = 1 << 30
	ringHeader  = 8
)

func openRing(fd int, size uint32) (*ring, error) {
	page := os.Getpagesize()
	consumer, err := unix.Mmap(fd, 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map the ring buffer's consumer page: %w", err)
	}
	producer, err := unix.Mmap(fd, int64(page), page+2*int(size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(consumer)
		return nil, fmt.Errorf("map the ring buffer: %w", err)
	}
	epoll, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		unix.Munmap(consumer)
		unix.Munmap(producer)
		return nil, err
	}
	if err := unix.EpollCtl(epoll, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		unix.Close(epoll)
		unix.Munmap(consumer)
		unix.Munmap(producer)
		return nil, err
	}
	return &ring{fd: fd, consumer: consumer, producer: producer, data: producer[page:], mask: uint64(size) - 1, epoll: epoll}, nil
}

// wait blocks until the kernel has written something, or timeoutMS passes.
func (r *ring) wait(timeoutMS int) error {
	events := make([]unix.EpollEvent, 1)
	_, err := unix.EpollWait(r.epoll, events, timeoutMS)
	if errors.Is(err, unix.EINTR) {
		return nil
	}
	return err
}

// read hands each finished record to handle, then tells the kernel the
// space is free.
func (r *ring) read(handle func([]byte)) {
	consumerPos := (*uint64)(unsafe.Pointer(&r.consumer[0]))
	producerPos := (*uint64)(unsafe.Pointer(&r.producer[0]))
	position := atomic.LoadUint64(consumerPos)
	for {
		end := atomic.LoadUint64(producerPos)
		if position >= end {
			break
		}
		header := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.data[position&r.mask])))
		if header&ringBusy != 0 {
			break
		}
		length := uint64(header &^ (ringBusy | ringDiscard))
		if header&ringDiscard == 0 {
			start := (position + ringHeader) & r.mask
			handle(r.data[start : start+length])
		}
		position += (ringHeader + length + 7) &^ 7
		atomic.StoreUint64(consumerPos, position)
	}
}

func (r *ring) close() {
	unix.Close(r.epoll)
	unix.Munmap(r.producer)
	unix.Munmap(r.consumer)
}
