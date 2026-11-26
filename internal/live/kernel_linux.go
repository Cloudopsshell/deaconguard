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

// The map types the loader treats apart: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
// which holds each CPU's perf buffer, and BPF_MAP_TYPE_RINGBUF.
const (
	mapTypePerfEventArray = 4
	mapTypeRingbuf        = 27
)

// attrSize is how much of union bpf_attr the loader fills; the kernel
// accepts a shorter or longer union as long as the rest is zero.
const attrSize = 128

// loadAttempts bounds how often a program's load is tried again when the
// kernel's checker gives up for a signal: the Go runtime signals its own
// threads to switch goroutines, and a long check can meet one.
const loadAttempts = 10

func bpf(cmd int, attr []byte) (int, error) {
	for attempt := 1; ; attempt++ {
		fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
		runtime.KeepAlive(attr)
		if errno == 0 {
			return int(fd), nil
		}
		if (errno == unix.EAGAIN || errno == unix.EINTR) && cmd == cmdProgLoad && attempt < loadAttempts {
			continue
		}
		return -1, errno
	}
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
	return "", errors.New("the kernel's tracing file system (tracefs) isn't mounted on this machine (in Kubernetes, on the node): mount it at /sys/kernel/tracing, as systemd does at boot")
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

// ringbufSupported reports whether the kernel has the ring buffer, new in
// Linux 5.8 and in some vendors' older kernels, such as RHEL 8's: it tries
// to make a small one. Without the right to try, it says yes, so the
// error that matters comes from loading the watchers.
func ringbufSupported() bool {
	fd, err := createMap(MapSpec{Name: "probe", Type: mapTypeRingbuf, MaxEntries: uint32(os.Getpagesize())})
	if err == nil {
		unix.Close(fd)
		return true
	}
	return !errors.Is(err, unix.EINVAL)
}

// raiseLockedMemory lifts the locked-memory limit, which kernels before
// 5.11 charge the watchers' maps to; its default of 64 KiB is too small
// for them. Later kernels count the maps elsewhere and need nothing.
func raiseLockedMemory() {
	if KernelRelease() == "" || kernelAtLeast(5, 11) {
		return
	}
	unlimited := &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, unlimited)
}

// events is where the agent reads the watchers' events from: the ring
// buffer, or on older kernels, a perf buffer per CPU.
type events interface {
	wait(timeoutMS int) error
	read(handle func([]byte))
	close()
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

// perfBuffers reads the watchers' per-CPU perf buffers, for kernels
// without the ring buffer. Each is a metadata page, where the kernel
// writes how far it has written (data_head) and the agent how far it has
// read (data_tail), then the data, records the kernel wraps around its end.
type perfBuffers struct {
	maps  [][]byte
	fds   []int
	epoll int
	size  uint64
	page  int
	// record holds a record that wraps around the end of its buffer.
	record []byte
}

const (
	perfHeadOffset = 1024
	perfTailOffset = 1032
	perfHeaderSize = 8
	// perfBudget is how much memory the perf buffers take together, like
	// the ring buffer's 256 KiB, but at least perfMinimum per CPU.
	perfBudget  = 256 << 10
	perfMinimum = 32 << 10
)

// perfBufferSize is the data size of each CPU's buffer: a power of two
// pages, within perfBudget for all CPUs unless that's below perfMinimum.
func perfBufferSize(cpus, page int) int {
	size := perfMinimum
	for size*2*cpus <= perfBudget {
		size *= 2
	}
	if size < page {
		size = page
	}
	return size
}

func openPerfBuffers(mapFD, cpus int) (*perfBuffers, error) {
	page := os.Getpagesize()
	size := perfBufferSize(cpus, page)
	epoll, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	p := &perfBuffers{epoll: epoll, size: uint64(size), page: page, record: make([]byte, 0, 1024)}
	key, value := make([]byte, 4), make([]byte, 4)
	for cpu := 0; cpu < cpus; cpu++ {
		attr := unix.PerfEventAttr{
			Type:        unix.PERF_TYPE_SOFTWARE,
			Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
			Sample_type: unix.PERF_SAMPLE_RAW,
			Sample:      1,
			Wakeup:      1,
		}
		attr.Size = uint32(unsafe.Sizeof(attr))
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if errors.Is(err, unix.ENODEV) {
			// A CPU that's possible but not present.
			continue
		}
		if err != nil {
			p.close()
			return nil, fmt.Errorf("open the perf buffer of CPU %d: %w", cpu, err)
		}
		mapped, err := unix.Mmap(fd, 0, page+size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			unix.Close(fd)
			p.close()
			return nil, fmt.Errorf("map the perf buffer of CPU %d: %w", cpu, err)
		}
		p.fds = append(p.fds, fd)
		p.maps = append(p.maps, mapped)
		binary.LittleEndian.PutUint32(key, uint32(cpu))
		binary.LittleEndian.PutUint32(value, uint32(fd))
		if err := updateMap(mapFD, key, value); err != nil {
			p.close()
			return nil, fmt.Errorf("hand the perf buffer of CPU %d to the watchers: %w", cpu, err)
		}
		if err := unix.EpollCtl(epoll, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			p.close()
			return nil, err
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			p.close()
			return nil, fmt.Errorf("enable the perf buffer of CPU %d: %w", cpu, err)
		}
	}
	if len(p.fds) == 0 {
		p.close()
		return nil, errors.New("no CPU took a perf buffer")
	}
	return p, nil
}

func (p *perfBuffers) wait(timeoutMS int) error {
	ready := make([]unix.EpollEvent, len(p.fds))
	_, err := unix.EpollWait(p.epoll, ready, timeoutMS)
	if errors.Is(err, unix.EINTR) {
		return nil
	}
	return err
}

// read hands each sample in every CPU's buffer to handle, then tells the
// kernel the space is free. Lost records need nothing: the watchers count
// what they couldn't hand over.
func (p *perfBuffers) read(handle func([]byte)) {
	for _, mapped := range p.maps {
		head := atomic.LoadUint64((*uint64)(unsafe.Pointer(&mapped[perfHeadOffset])))
		tailPointer := (*uint64)(unsafe.Pointer(&mapped[perfTailOffset]))
		tail := atomic.LoadUint64(tailPointer)
		data := mapped[p.page:]
		for tail+perfHeaderSize <= head {
			header := p.copy(data, tail, perfHeaderSize)
			kind := binary.LittleEndian.Uint32(header[0:])
			size := uint64(binary.LittleEndian.Uint16(header[6:]))
			if size < perfHeaderSize || tail+size > head {
				break
			}
			if kind == unix.PERF_RECORD_SAMPLE && size >= perfHeaderSize+4 {
				record := p.copy(data, tail, size)
				length := uint64(binary.LittleEndian.Uint32(record[perfHeaderSize:]))
				if perfHeaderSize+4+length <= size {
					handle(record[perfHeaderSize+4 : perfHeaderSize+4+length])
				}
			}
			tail += size
		}
		atomic.StoreUint64(tailPointer, tail)
	}
}

// copy returns length bytes of a buffer from position, joining a record
// that wraps around its end into p.record.
func (p *perfBuffers) copy(data []byte, position, length uint64) []byte {
	start := position % p.size
	if start+length <= p.size {
		return data[start : start+length]
	}
	p.record = append(p.record[:0], data[start:p.size]...)
	p.record = append(p.record, data[:length-(p.size-start)]...)
	return p.record
}

func (p *perfBuffers) close() {
	for _, fd := range p.fds {
		unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
	}
	for _, mapped := range p.maps {
		unix.Munmap(mapped)
	}
	for _, fd := range p.fds {
		unix.Close(fd)
	}
	unix.Close(p.epoll)
	p.maps, p.fds = nil, nil
}
