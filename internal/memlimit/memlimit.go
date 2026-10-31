// Package memlimit tells the Go runtime the memory limit the process runs
// under: a container's, or a systemd unit's MemoryMax. Without it, the
// garbage collector lets the heap grow to twice the memory in use before it
// collects, and a server parsing a large feed can pass a container's limit
// and be stopped by the kernel while half of that is garbage.
package memlimit

import (
	"bufio"
	"os"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

// share is the part of the limit the Go heap may use before the collector
// works harder; the rest is for stacks, the runtime and the page cache.
const share = 85

// unlimited is where cgroup v1 reports no limit: a number near the largest
// int64, rounded to the page size.
const unlimited = 1 << 60

// Limit is the memory limit the process runs under, in bytes, or 0 when
// there is none.
var Limit = sync.OnceValue(func() int64 { return read("/proc/self/cgroup", "/sys/fs/cgroup") })

// Apply sets the Go runtime's soft memory limit to share percent of Limit,
// unless GOMEMLIMIT sets it already or there is no limit.
func Apply() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	if limit := Limit(); limit > 0 {
		debug.SetMemoryLimit(limit / 100 * share)
	}
}

// read finds the limit of the process's cgroup, given /proc/self/cgroup and
// where cgroups are mounted: the lowest memory.max on the way from its
// cgroup up to the root on cgroup v2, else memory.limit_in_bytes on v1.
func read(selfCgroup, root string) int64 {
	file, err := os.Open(selfCgroup)
	if err != nil {
		return 0
	}
	defer file.Close()
	var unified, v1 string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// hierarchy-ID:controllers:path
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			unified = parts[2]
		}
		for _, controller := range strings.Split(parts[1], ",") {
			if controller == "memory" {
				v1 = parts[2]
			}
		}
	}
	if v1 != "" {
		return lowest(path.Join(root, "memory"), v1, "memory.limit_in_bytes")
	}
	if unified != "" {
		return lowest(root, unified, "memory.max")
	}
	return 0
}

// lowest reads name in dir and each of its parents up to mount, and returns
// the lowest limit set. In a container the process's cgroup is the
// namespace's root, so only the mount's own file is read.
func lowest(mount, dir, name string) int64 {
	limit := int64(0)
	for current := path.Clean("/" + dir); ; current = path.Dir(current) {
		if value := readLimit(path.Join(mount, current, name)); value > 0 && (limit == 0 || value < limit) {
			limit = value
		}
		if current == "/" {
			return limit
		}
	}
}

func readLimit(file string) int64 {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	// "max" on v2, or a huge number on v1, is no limit.
	if err != nil || value <= 0 || value >= unlimited {
		return 0
	}
	return value
}
