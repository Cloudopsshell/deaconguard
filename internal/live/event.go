package live

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// The kinds of event the watchers report.
const (
	KindExec  = 1
	KindWrite = 2
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
}

// eventSize and the offsets below follow struct event in bpf/watch.c.
const eventSize = 840

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
	return Event{
		Kind:   int(little.Uint32(raw[0:])),
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
