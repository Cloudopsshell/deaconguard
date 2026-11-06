package live

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
)

// The kinds of event the watchers report.
const (
	KindExec    = 1
	KindWrite   = 2
	KindConnect = 3
	// KindPrivilege: a process that isn't root switched to root.
	KindPrivilege = 4
	// KindModule: a kernel module was loaded, or a load was tried.
	KindModule = 5
	// KindTrace: a process took control of another with ptrace, or wrote
	// into its memory.
	KindTrace = 6
)

// Which call an event of the last three kinds reports, in Event.How.
const (
	CallSetUID     = 1
	CallSetREUID   = 2
	CallSetRESUID  = 3
	CallFileModule = 1
	CallMemModule  = 2
	CallAttach     = 16
	CallSeize      = 0x4206
	CallVMWrite    = 0x10000
)

// Why the watchers reported a connection.
const (
	// WhyMarked: the process, or one that started it, started from a
	// temporary folder or memory.
	WhyMarked = 1
	// WhyPort: the port is one of watchedPorts.
	WhyPort = 2
	// WhyComm: the process is a shell.
	WhyComm = 4
)

// How a watched file was written.
const (
	HowOpen   = 1
	HowRename = 2
	HowLink   = 3
)

// Event is one event from the watchers.
type Event struct {
	Kind     int
	PID, TID uint32
	UID      uint32
	// TimeNS is the kernel's monotonic clock.
	TimeNS uint64
	Cgroup uint64
	How    int
	// Comm is the process's name; for a program that started, its new name.
	Comm string
	// Parent is, for a program that started, the name of the program that
	// started it: the process's name just before exec.
	Parent string
	// Path is the program that started, or the file written.
	Path string
	// Args is the program's arguments, joined by spaces, at most 256 bytes.
	Args string
	// Address and Port are where a connection went, and Why why it was
	// reported (the Why constants).
	Address netip.Addr
	Port    uint16
	Why     int
	// Target is the process traced or written into, as the caller numbers
	// it (in its own process namespace), or a module's file descriptor.
	Target uint32
	// Result is what the system call returned: 0 or more if it worked, an
	// error number, negated, if it didn't.
	Result int64
	// IDs are the user IDs a privilege change asked for; 0xffffffff leaves
	// one as it was.
	IDs [3]uint32
	// Marked: the process, or one that started it, started from a
	// temporary folder or memory.
	Marked bool
}

// eventSize and the offsets below follow struct event in bpf/watch.c.
const eventSize = 840

// Address families, as the kernel numbers them.
const (
	familyIPv4 = 2
	familyIPv6 = 10
)

var errShortEvent = errors.New("event shorter than the watchers write")

// ParseEvent reads one event from the ring buffer.
func ParseEvent(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, errShortEvent
	}
	little := binary.LittleEndian
	argsLen := int(little.Uint32(raw[36:]))
	args := raw[328:840]
	if argsLen > 0 && argsLen <= len(args) {
		args = args[:argsLen]
	}
	kind := int(little.Uint32(raw[0:]))
	if kind == KindPrivilege || kind == KindModule || kind == KindTrace {
		// The call's target is in args_len, and its outcome in path:
		// result, the three IDs, and whether the process is marked.
		event := Event{
			Kind:   kind,
			PID:    little.Uint32(raw[4:]),
			TID:    little.Uint32(raw[8:]),
			UID:    little.Uint32(raw[12:]),
			TimeNS: little.Uint64(raw[16:]),
			Cgroup: little.Uint64(raw[24:]),
			How:    int(little.Uint32(raw[32:])),
			Target: little.Uint32(raw[36:]),
			Comm:   cString(raw[40:56]),
			Result: int64(little.Uint64(raw[72:])),
			IDs:    [3]uint32{little.Uint32(raw[80:]), little.Uint32(raw[84:]), little.Uint32(raw[88:])},
			Marked: little.Uint32(raw[92:]) != 0,
		}
		if kind == KindModule {
			event.Args = cString(raw[328:584])
		}
		return event, nil
	}
	if kind == KindConnect {
		// The connection's port is in how, its address family in
		// args_len, the address in path and why it was reported in args.
		event := Event{
			Kind:   kind,
			PID:    little.Uint32(raw[4:]),
			TID:    little.Uint32(raw[8:]),
			UID:    little.Uint32(raw[12:]),
			TimeNS: little.Uint64(raw[16:]),
			Cgroup: little.Uint64(raw[24:]),
			Port:   uint16(little.Uint32(raw[32:])),
			Comm:   cString(raw[40:56]),
			Why:    int(raw[328]),
		}
		switch little.Uint32(raw[36:]) {
		case familyIPv4:
			event.Address = netip.AddrFrom4([4]byte(raw[72:76]))
		case familyIPv6:
			event.Address = netip.AddrFrom16([16]byte(raw[72:88])).Unmap()
		}
		return event, nil
	}
	return Event{
		Kind:   kind,
		PID:    little.Uint32(raw[4:]),
		TID:    little.Uint32(raw[8:]),
		UID:    little.Uint32(raw[12:]),
		TimeNS: little.Uint64(raw[16:]),
		Cgroup: little.Uint64(raw[24:]),
		How:    int(little.Uint32(raw[32:])),
		Comm:   cString(raw[40:56]),
		Parent: cString(raw[56:72]),
		Path:   cString(raw[72:328]),
		Args:   string(bytes.TrimRight(cStringBytes(args), " ")),
	}, nil
}

func cStringBytes(raw []byte) []byte {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		return raw[:end]
	}
	return raw
}

func cString(raw []byte) string { return string(cStringBytes(raw)) }
