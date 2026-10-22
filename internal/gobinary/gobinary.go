// Package gobinary reads the build information Go 1.18 and later write into
// every program: the Go version it was built with and the modules it
// contains. It reads it from a stream, so whole binaries never have to be
// held in memory: a file on a host, or one passing by in an image layer.
// The Go version is checked against OSV as the module "stdlib", which is
// how OSV lists Go's own vulnerabilities, such as crypto/x509's GO-2026-6809.
package gobinary

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strconv"
	"strings"
)

// magic starts Go's build information block; it is 16-byte aligned.
var magic = []byte("\xff Go buildinf:")

const (
	align      = 16
	headerSize = 32
	// flagInline marks Go 1.18 and later, whose block holds the version and
	// module strings inline after the header.
	flagInline = 0x2
	// maxModInfo bounds the module list, which is a few kilobytes even for
	// programs with hundreds of modules.
	maxModInfo = 4 << 20
	chunkSize  = 1 << 20
	// MaxProgramBytes is the largest program read.
	MaxProgramBytes = 512 << 20
)

// DistroDir reports whether a program at path is in a folder of the
// distribution's own programs, whose Go programs the distribution patches
// without changing the Go version they record. Where a machine or image has
// a package database, the package check covers them instead.
func DistroDir(path string) bool {
	for _, dir := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/"} {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return false
}

// Module is one Go module in a program.
type Module struct {
	Path, Version string
}

// Info is a program's build information.
type Info struct {
	// GoVersion is as Go records it, such as "go1.26.9".
	GoVersion string
	Main      Module
	Deps      []Module
}

// ErrNotGo means the stream holds no Go 1.18+ build information.
var ErrNotGo = errors.New("no Go build information")

// Executable reports whether data starts like a program DeaconGuard can read:
// ELF (Linux) or Mach-O (macOS, including universal binaries).
func Executable(start []byte) bool {
	if len(start) < 4 {
		return false
	}
	switch {
	case bytes.HasPrefix(start, []byte("\x7fELF")):
		return true
	case bytes.Equal(start[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.Equal(start[:4], []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.Equal(start[:4], []byte{0xca, 0xfe, 0xba, 0xbe}):
		return true
	}
	return false
}

// Read finds the build information in r, reading at most limit bytes. It
// reads on past text that merely contains the magic, such as a program
// that uses debug/buildinfo itself, until a block decodes.
func Read(r io.Reader, limit int64) (Info, error) {
	reader := bufio.NewReaderSize(io.LimitReader(r, limit), chunkSize)
	var buf []byte
	var base int64 // the stream offset of buf[0]
	eof := false
	fill := func(need int) {
		for len(buf) < need && !eof {
			chunk := make([]byte, chunkSize)
			n, err := io.ReadFull(reader, chunk)
			buf = append(buf, chunk[:n]...)
			if err != nil {
				eof = true
			}
		}
	}
	searchFrom := 0
	for {
		fill(searchFrom + chunkSize)
		index := bytes.Index(buf[searchFrom:], magic)
		if index < 0 {
			if eof {
				return Info{}, ErrNotGo
			}
			// Keep a tail, so a magic split across chunks is found.
			keep := len(magic) - 1
			if len(buf) > keep {
				base += int64(len(buf) - keep)
				buf = append([]byte(nil), buf[len(buf)-keep:]...)
			}
			searchFrom = 0
			continue
		}
		at := searchFrom + index
		if (base+int64(at))%align != 0 {
			searchFrom = at + 1
			continue
		}
		fill(at + headerSize + 2*binary.MaxVarintLen64)
		info, need, ok := decode(buf[at:])
		// The version and the module list may each need more of the stream.
		for need > len(buf)-at && !eof {
			fill(at + need)
			info, need, ok = decode(buf[at:])
		}
		if ok {
			return info, nil
		}
		searchFrom = at + 1
	}
}

// decode reads a block at the start of data. need > 0 asks for that many
// bytes when data is too short to tell.
func decode(data []byte) (Info, int, bool) {
	if len(data) < headerSize {
		return Info{}, headerSize, false
	}
	pointerSize, flags := data[len(magic)], data[len(magic)+1]
	if (pointerSize != 4 && pointerSize != 8) || flags&flagInline == 0 {
		return Info{}, 0, false
	}
	rest := data[headerSize:]
	version, rest, need := readString(rest, 64)
	if need > 0 {
		return Info{}, headerSize + need, false
	}
	if version == nil || !(bytes.HasPrefix(version, []byte("go1")) || bytes.HasPrefix(version, []byte("devel"))) {
		return Info{}, 0, false
	}
	modInfo, _, need := readString(rest, maxModInfo)
	if need > 0 {
		return Info{}, headerSize + len(data[headerSize:]) - len(rest) + need, false
	}
	info := Info{GoVersion: string(version)}
	// The module list is wrapped in 16-byte sentinels.
	if len(modInfo) >= 33 && modInfo[len(modInfo)-17] == '\n' {
		if parsed, err := debug.ParseBuildInfo(string(modInfo[16 : len(modInfo)-16])); err == nil {
			info.Main = Module{parsed.Main.Path, parsed.Main.Version}
			for _, dep := range parsed.Deps {
				module := Module{dep.Path, dep.Version}
				if dep.Replace != nil && dep.Replace.Version != "" {
					module = Module{dep.Replace.Path, dep.Replace.Version}
				}
				info.Deps = append(info.Deps, module)
			}
		}
	}
	return info, 0, true
}

// readString reads a varint length and that many bytes. need > 0 is how many
// more bytes (from data's start) it needs; nil means the length is invalid.
func readString(data []byte, limit uint64) ([]byte, []byte, int) {
	length, n := binary.Uvarint(data)
	if n == 0 {
		return nil, data, binary.MaxVarintLen64
	}
	if n < 0 || length > limit {
		return nil, data, 0
	}
	if uint64(len(data)-n) < length {
		return nil, data, n + int(length)
	}
	return data[n : n+int(length)], data[n+int(length):], 0
}

// StdlibVersion is the Go version as OSV's "stdlib" module versions it:
// "go1.26.9" is 1.26.9, "go1.21rc2" 1.21.0-rc.2, and "go1.20" 1.20.0. A
// development or unreadable version gives "". OSV matches an unparseable
// version against every advisory, so this must never pass one through.
func StdlibVersion(goVersion string) string {
	version, _, _ := strings.Cut(strings.TrimPrefix(goVersion, "go"), " ")
	version, _, _ = strings.Cut(version, "-")
	pre := ""
	for _, kind := range []string{"rc", "beta"} {
		if before, after, found := strings.Cut(version, kind); found {
			if _, err := strconv.Atoi(after); err != nil {
				return ""
			}
			version, pre = before, "-"+kind+"."+after
		}
	}
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return ""
	}
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return ""
		}
	}
	if len(parts) == 2 {
		parts = append(parts, "0")
	}
	return strings.Join(parts, ".") + pre
}

// RecordMarker starts a record of a Go program in the library check's
// output, in place of a file's contents; no real file starts with it.
const RecordMarker = "\x00deaconguard-go-binary\n"

// Record is the program's modules as a library-check record body: a marker,
// then "stdlib", the main module and each dependency, one per line as
// "path<TAB>version". Modules without a release version are left out.
func (info Info) Record() []byte {
	var b strings.Builder
	b.WriteString(RecordMarker)
	if version := StdlibVersion(info.GoVersion); version != "" {
		fmt.Fprintf(&b, "stdlib\t%s\n", version)
	}
	for _, module := range append([]Module{info.Main}, info.Deps...) {
		if module.Path == "" || module.Version == "" || module.Version == "(devel)" || strings.ContainsAny(module.Path+module.Version, "\t\n") {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\n", module.Path, module.Version)
	}
	return []byte(b.String())
}
