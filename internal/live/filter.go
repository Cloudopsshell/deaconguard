package live

// The watchers' path filters, as struct watched and struct name in
// bpf/watch.c lay them out: text as little-endian words, with masks
// selecting the bytes that must match.

const (
	filterPrefix = 1
	filterThen   = 2
)

// watchedPathValue is one struct watched: prefix (at most 48 bytes), and
// for paths such as /home/NAME/.ssh/, what must follow one more folder.
func watchedPathValue(prefix, after string) []byte {
	value := make([]byte, 120)
	copy(value[0:48], prefix)
	for i := 0; i < len(prefix) && i < 48; i++ {
		value[48+i] = 0xff
	}
	copy(value[96:104], after)
	for i := 0; i < len(after) && i < 8; i++ {
		value[104+i] = 0xff
	}
	putUint32(value[112:], uint32(len(prefix)))
	kind := uint32(filterPrefix)
	if after != "" {
		kind = filterThen
	}
	putUint32(value[116:], kind)
	return value
}

// watchedNameValue is one struct name: the name and its terminating zero,
// at most 32 bytes, so only that exact name matches.
func watchedNameValue(name string) []byte {
	value := make([]byte, 64)
	copy(value[0:32], name)
	for i := 0; i <= len(name) && i < 32; i++ {
		value[32+i] = 0xff
	}
	return value
}

func putUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
