package containers

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"deaconguard/internal/local"
)

// Writable is a running container's own files, as folders on the host:
// its writable layer, where everything it wrote or changed since it
// started is, and its Kubernetes emptyDir volumes, the scratch space pods
// with a read-only root file system write to. Malware dropped at runtime
// lands in one of them. The image's layers underneath are left out: they
// are shared by every container of the image, and checked as images.
type Writable struct {
	ID   string // the container's ID
	Name string
	Dirs []WritableDir
}

// WritableDir is one folder of a container: HostPath on the host, seen as
// Path inside the container.
type WritableDir struct {
	HostPath string
	Path     string
}

// MaxWritableDirs bounds the folders a malware scan adds for containers.
const MaxWritableDirs = 600

// emptyDirPath is in the host path of a Kubernetes emptyDir volume, as
// kubelet makes it: /var/lib/kubelet/pods/UID/volumes/kubernetes.io~empty-dir/NAME.
const emptyDirPath = "/volumes/kubernetes.io~empty-dir/"

// FindWritable finds the writable folders of the running containers from
// the kernel's mount tables: each container's root mount (overlay, whose
// upperdir is its writable layer) and its emptyDir mounts, translated to
// host paths with the host's own mount table. Containers on other storage
// drivers, such as btrfs or ZFS, have no upper layer to find; skipped
// counts them. Folders shared by several containers, such as a pod's
// emptyDir, are kept once. Every running container is returned, with no
// folders when none were found, so processes can be named after theirs.
func FindWritable(list []Container) (found []Writable, skipped int) {
	host, _ := readMountInfo(1)
	seen := make(map[string]bool)
	total := 0
	for _, container := range list {
		if !container.Running() {
			continue
		}
		writable := Writable{ID: container.ID, Name: container.Name}
		var dirs []WritableDir
		if mounts, err := readMountInfo(container.pid); err == nil {
			dirs = writableDirs(mounts, host)
		}
		if len(dirs) == 0 {
			skipped++
		}
		for _, dir := range dirs {
			if seen[dir.HostPath] || total >= MaxWritableDirs || !isHostDir(dir.HostPath) {
				continue
			}
			seen[dir.HostPath] = true
			total++
			writable.Dirs = append(writable.Dirs, dir)
		}
		found = append(found, writable)
	}
	return found, skipped
}

// writableDirs reads a container's mounts: the root's upper layer, then
// its emptyDir volumes by where they are mounted.
func writableDirs(mounts, host []mountInfo) []WritableDir {
	var dirs []WritableDir
	for _, mount := range mounts {
		if mount.point == "/" && mount.fsType == "overlay" {
			if upper := mount.option("upperdir"); validHostPath(upper) {
				dirs = append(dirs, WritableDir{HostPath: upper, Path: "/"})
			}
		}
	}
	var volumes []WritableDir
	for _, mount := range mounts {
		if mount.point == "/" {
			continue
		}
		hostPath := hostPathOf(mount, host)
		if !strings.Contains(hostPath, emptyDirPath) || !validHostPath(hostPath) {
			continue
		}
		volumes = append(volumes, WritableDir{HostPath: hostPath, Path: mount.point})
	}
	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Path < volumes[j].Path })
	return append(dirs, volumes...)
}

// hostPathOf finds where a container's bind mount is on the host: the
// host mount of the same file system whose root holds the container's,
// the longest such root first.
func hostPathOf(mount mountInfo, host []mountInfo) string {
	best, bestRoot := "", -1
	for _, candidate := range host {
		if candidate.device != mount.device {
			continue
		}
		root := strings.TrimSuffix(candidate.root, "/")
		if mount.root != candidate.root && !strings.HasPrefix(mount.root, root+"/") {
			continue
		}
		if len(root) > bestRoot {
			best, bestRoot = filepath.Join(candidate.point, strings.TrimPrefix(mount.root, root)), len(root)
		}
	}
	return best
}

// validHostPath accepts clean absolute paths a shell list can carry.
func validHostPath(path string) bool {
	return strings.HasPrefix(path, "/") && filepath.Clean(path) == path && path != "/" &&
		!strings.ContainsAny(path, "\n\r\x00")
}

// isHostDir reports whether path is a directory on the host, not a link:
// the scanners are given it as their starting point.
func isHostDir(path string) bool {
	info, err := os.Lstat(local.HostPath(path))
	return err == nil && info.IsDir()
}

// mountInfo is one line of /proc/PID/mountinfo.
type mountInfo struct {
	device  string // major:minor
	root    string // the folder of the file system mounted here
	point   string
	fsType  string
	options string // the file system's own options
}

func (m mountInfo) option(name string) string {
	for _, option := range strings.Split(m.options, ",") {
		if value, found := strings.CutPrefix(option, name+"="); found {
			return unescapeMount(value)
		}
	}
	return ""
}

// readMountInfo reads a process's mount table, through the host's /proc
// when the agent runs in a container without the host's process list.
func readMountInfo(pid int) ([]mountInfo, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "mountinfo")
	data, err := os.ReadFile(path)
	if hostRoot := local.HostRoot(); err != nil && hostRoot != "" {
		data, err = os.ReadFile(filepath.Join(hostRoot, path))
	}
	if err != nil {
		return nil, err
	}
	return parseMountInfo(string(data)), nil
}

// parseMountInfo reads lines such as
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//
// Paths have spaces, tabs, newlines and backslashes escaped as octal.
func parseMountInfo(data string) []mountInfo {
	var mounts []mountInfo
	for _, line := range strings.Split(data, "\n") {
		before, after, found := strings.Cut(line, " - ")
		if !found {
			continue
		}
		fields, rest := strings.Fields(before), strings.Fields(after)
		if len(fields) < 5 || len(rest) < 3 {
			continue
		}
		mounts = append(mounts, mountInfo{
			device: fields[2], root: unescapeMount(fields[3]), point: unescapeMount(fields[4]),
			fsType: rest[0], options: rest[2],
		})
	}
	return mounts
}

// unescapeMount turns the kernel's \ooo escapes back into bytes.
func unescapeMount(value string) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+4 <= len(value) {
			if code, err := strconv.ParseUint(value[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

// ProcessContainer names the container a process runs in, from the
// container IDs in its cgroup path, such as
// 0::/kubepods/besteffort/pod…/cri-containerd-ID.scope or
// 0::/system.slice/docker-ID.scope; "" for the host's own processes.
func ProcessContainer(pid string, list []Writable) string {
	if len(list) == 0 {
		return ""
	}
	path := filepath.Join("/proc", pid, "cgroup")
	data, err := os.ReadFile(path)
	if hostRoot := local.HostRoot(); err != nil && hostRoot != "" {
		data, err = os.ReadFile(filepath.Join(hostRoot, path))
	}
	if err != nil {
		return ""
	}
	return containerInCgroup(string(data), list)
}

func containerInCgroup(cgroup string, list []Writable) string {
	for _, container := range list {
		if len(container.ID) >= 12 && strings.Contains(cgroup, container.ID) {
			return container.Name
		}
	}
	return ""
}
