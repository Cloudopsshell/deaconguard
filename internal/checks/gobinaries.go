package checks

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"deaconguard/internal/gobinary"
	"deaconguard/internal/local"
)

// Limits on reading compiled Go programs on a host.
const (
	maxGoExecutables = 20000
	maxGoBinaryBytes = 512 << 20
	maxGoReadBytes   = 16 << 30
	goWalkTimeout    = 10 * time.Minute
)

// goBinaryRoots are walked like the library check's find roots, each on its
// own file system.
var goBinaryRoots = []string{"/", "/home", "/opt", "/srv", "/usr/local", "/var/www", "/root"}

// goBinarySkipped are left out: kernel and device file systems, the
// distribution's own program and library folders, whose Go programs the
// distribution patches without changing the Go version they record (the
// package check covers them with its advisories), and container storage,
// which the container check reads container by container.
var goBinarySkipped = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true, "/boot": true, "/snap": true,
	"/bin": true, "/sbin": true, "/usr/bin": true, "/usr/sbin": true, "/lib": true, "/lib32": true, "/lib64": true,
	"/usr/lib": true, "/usr/lib32": true, "/usr/lib64": true, "/usr/libexec": true,
	"/var/lib/docker": true, "/var/lib/containerd": true, "/var/lib/containers": true, "/var/lib/kubelet": true,
}

// OnThisMachine reports whether the executor runs commands on the machine
// DeaconGuard runs on, whose files the checks may then read directly.
func (e *Executor) OnThisMachine() bool {
	_, ok := e.commander.(*local.Target)
	return ok
}

func deviceOf(info os.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), true
	}
	return 0, false
}

// collectGoBinaries finds the compiled Go programs outside the
// distribution's folders and returns their build information as library
// records (gobinary.Record), with notes on what it couldn't finish. It only
// reads: it never runs a program.
func collectGoBinaries() ([]byte, []string) {
	var records bytes.Buffer
	var notes []string
	visited := map[string]bool{}
	examined, found := 0, 0
	var read int64
	deadline := time.Now().Add(goWalkTimeout)
	stopped := ""
	var walk func(dir string, device uint64)
	walk = func(dir string, device uint64) {
		if stopped != "" || visited[dir] {
			return
		}
		visited[dir] = true
		if time.Now().After(deadline) {
			stopped = "Reading Go programs stopped after 10 minutes; some may be missing."
			return
		}
		entries, err := os.ReadDir(local.HostPath(dir))
		if err != nil {
			return
		}
		for _, entry := range entries {
			path := strings.TrimSuffix(dir, "/") + "/" + entry.Name()
			if entry.IsDir() {
				if goBinarySkipped[path] || entry.Name() == ".git" || entry.Name() == "node_modules" {
					continue
				}
				if info, err := entry.Info(); err == nil {
					if dev, ok := deviceOf(info); ok && dev == device {
						walk(path, device)
					}
				}
				continue
			}
			if !entry.Type().IsRegular() {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.Mode().Perm()&0o111 == 0 || info.Size() < 1024 || info.Size() > maxGoBinaryBytes {
				continue
			}
			if examined >= maxGoExecutables || read > maxGoReadBytes {
				stopped = "More than 20,000 programs or 16 GB to read; some Go programs may be missing."
				return
			}
			examined++
			record, size := readGoBinary(local.HostPath(path))
			read += size
			if record != nil {
				found++
				records.WriteByte(0x1e)
				records.WriteString(path)
				records.WriteByte('\n')
				records.Write(record)
				records.WriteByte('\n')
			}
		}
	}
	for _, root := range goBinaryRoots {
		info, err := os.Stat(local.HostPath(root))
		if err != nil || !info.IsDir() {
			continue
		}
		if device, ok := deviceOf(info); ok {
			walk(root, device)
		}
	}
	if stopped != "" {
		notes = append(notes, stopped)
	}
	return records.Bytes(), notes
}

// readGoBinary reads one file's Go build information, without following a
// symbolic link, and reports how many bytes it read.
func readGoBinary(path string) ([]byte, int64) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, 0
	}
	counter := &countingReader{r: file}
	start := make([]byte, 4)
	if _, err := io.ReadFull(counter, start); err != nil || !gobinary.Executable(start) {
		return nil, counter.n
	}
	info, err := gobinary.Read(io.MultiReader(bytes.NewReader(start), counter), maxGoBinaryBytes)
	if err != nil {
		return nil, counter.n
	}
	return info.Record(), counter.n
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// goBinaryNote says how many Go programs a library result came from.
func goBinaryNote(records []byte) string {
	count := bytes.Count(records, []byte(gobinary.RecordMarker))
	if count == 0 {
		return ""
	}
	return fmt.Sprintf("Read the Go version and modules of %d compiled Go programs; the distribution's own folders (/usr/bin, /usr/lib and the like) are left to the package check.", count)
}
