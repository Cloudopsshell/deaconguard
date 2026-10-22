// Package containers finds the containers running on a machine (Docker,
// Podman, and containerd or CRI-O through crictl) and reads what is
// installed in each: the OS packages and the application libraries.
//
// Nothing inside a container is run. The host's own docker, podman or
// crictl lists the containers, with fixed commands; the agent then reads
// each container's files itself, through /proc/PID/root, without following
// any symbolic link (see saferead_linux.go), so a container can't make it
// read a file outside the container.
package containers

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"deaconguard/internal/inventory"
	"deaconguard/internal/libraries"
	"deaconguard/internal/local"
)

// Limits keep a machine with many large containers within what an agent
// sends in one result.
const (
	MaxContainers   = 300
	maxPackageBytes = 32 << 20
	maxRPMDBBytes   = 128 << 20
	maxWalkDirs     = 200000
	walkTimeout     = 2 * time.Minute
)

// ListCommand lists running containers, one per line:
// PID|ID|name|image|image ID|runtime. Each runtime is asked only if its
// command exists; a failure of one doesn't stop the others.
const ListCommand = `{ command -v docker >/dev/null 2>&1 && docker ps --no-trunc --format '{{.ID}}' 2>/dev/null | head -n 300 | while read -r id; do ` +
	`docker inspect --format '{{.State.Pid}}|{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.Image}}|docker' "$id" 2>/dev/null; done; } ; ` +
	`{ command -v podman >/dev/null 2>&1 && podman ps --no-trunc --format '{{.ID}}' 2>/dev/null | head -n 300 | while read -r id; do ` +
	`podman inspect --format '{{.State.Pid}}|{{.Id}}|{{.Name}}|{{.ImageName}}|{{.Image}}|podman' "$id" 2>/dev/null; done; } ; ` +
	`{ command -v crictl >/dev/null 2>&1 && crictl ps -q 2>/dev/null | head -n 300 | while read -r id; do ` +
	`crictl inspect -o go-template --template '{{.info.pid}}|{{.status.id}}|{{index .status.labels "io.kubernetes.pod.namespace"}}/{{index .status.labels "io.kubernetes.pod.name"}}/{{.status.metadata.name}}|{{.status.image.image}}|{{.status.imageRef}}|cri' "$id" 2>/dev/null; echo; done; } ; true`

// Container is one running container.
type Container struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"image_id"`
	Runtime string `json:"runtime"`
	pid     int
}

// Inventory is what was read from one container, in the same formats the
// host scan uses, with the package lists cut down to the fields evaluated.
type Inventory struct {
	Container
	OSRelease    string            `json:"os_release,omitempty"`
	DPKGStatus   string            `json:"dpkg_status,omitempty"`
	RPMQuery     string            `json:"rpm_query,omitempty"`
	APKInstalled string            `json:"apk_installed,omitempty"`
	Libraries    *libraries.Result `json:"libraries,omitempty"`
	// Notes say what couldn't be read, such as a distroless image's missing
	// package database.
	Notes []string `json:"notes,omitempty"`
}

// ParseList reads ListCommand's output. Containers without a running
// process, and repeats, are skipped.
func ParseList(output []byte) []Container {
	var list []Container
	seen := make(map[int]bool)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) != 6 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		name := strings.TrimPrefix(fields[2], "/")
		if fields[5] == "cri" {
			name = strings.TrimPrefix(name, "/")
		}
		list = append(list, Container{ID: fields[1], Name: name, Image: fields[3], ImageID: fields[4], Runtime: fields[5], pid: pid})
		if len(list) >= MaxContainers {
			break
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// Read reads one container's OS packages and libraries. It needs root.
func Read(container Container) Inventory {
	result := Inventory{Container: container}
	// The agent's own /proc shows the host's processes on a host, and in a
	// Kubernetes DaemonSet with hostPID; otherwise the host's /proc, under
	// the host root, may.
	path := filepath.Join("/proc", strconv.Itoa(container.pid), "root")
	r, err := openRoot(path)
	if hostRoot := local.HostRoot(); err != nil && hostRoot != "" {
		r, err = openRoot(filepath.Join(hostRoot, path))
	}
	if err != nil {
		result.Notes = append(result.Notes, "Couldn't open the container's filesystem: "+err.Error())
		return result
	}
	defer r.close()
	return ReadFS(r, container)
}

// ReadFS reads the OS packages and libraries from a container's or an
// image's files.
func ReadFS(r FS, container Container) Inventory {
	result := Inventory{Container: container}
	result.OSRelease = readFirst(r, &result, 16<<10, "/etc/os-release", "/usr/lib/os-release")
	if result.OSRelease == "" {
		result.Notes = append(result.Notes, "No /etc/os-release: a distroless or scratch image, or one DeaconGuard can't identify; its libraries are still checked")
	}
	switch {
	case exists(r, "/var/lib/dpkg/status") || exists(r, "/var/lib/dpkg/status.d"):
		result.DPKGStatus = readDPKG(r, &result)
	case exists(r, "/lib/apk/db/installed"):
		if data := readFirst(r, &result, maxPackageBytes, "/lib/apk/db/installed"); data != "" {
			if packages, err := inventory.ParseAPKInstalled(data); err == nil {
				result.APKInstalled = compactAPK(packages)
			}
		}
	case exists(r, "/var/lib/rpm/rpmdb.sqlite") || exists(r, "/usr/lib/sysimage/rpm/rpmdb.sqlite"):
		for _, file := range []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite"} {
			data, truncated, err := r.ReadFile(file, maxRPMDBBytes)
			if err != nil {
				continue
			}
			if truncated {
				result.Notes = append(result.Notes, file+" is larger than 128 MB and wasn't read")
				break
			}
			query, err := rpmQueryFromSQLite(data)
			if err != nil {
				result.Notes = append(result.Notes, "Couldn't read the RPM database: "+err.Error())
			}
			result.RPMQuery = query
			break
		}
	case exists(r, "/var/lib/rpm/Packages") || exists(r, "/usr/lib/sysimage/rpm/Packages.db"):
		result.Notes = append(result.Notes, "The image's RPM database is in Berkeley DB or ndb format (RHEL 8, SUSE), which DeaconGuard can't read yet; only its libraries are checked")
	}
	packaged := result.DPKGStatus != "" || result.APKInstalled != "" || result.RPMQuery != ""
	found := walkLibraries(r, packaged)
	result.Libraries = &found
	return result
}

func exists(r FS, path string) bool {
	if _, _, err := r.ReadFile(path, 0); err == nil {
		return true
	}
	_, err := r.ReadDir(path)
	return err == nil
}

// readFirst returns the first of files that can be read; a note says why
// one couldn't, unless it doesn't exist.
func readFirst(r FS, result *Inventory, limit int64, files ...string) string {
	var refused []string
	defer func() {
		// Only worth saying when nothing could be read: /etc/os-release, for
		// one, is a link in almost every image, and the real file is read.
		if len(refused) == len(files) {
			result.Notes = append(result.Notes, refused...)
		}
	}()
	for _, file := range files {
		data, truncated, err := r.ReadFile(file, limit)
		if err != nil {
			if errors.Is(err, ErrSymlink) {
				refused = append(refused, err.Error())
			}
			continue
		}
		if truncated {
			result.Notes = append(result.Notes, fmt.Sprintf("%s is larger than %d MB; only the start was read", file, limit>>20))
		}
		return string(data)
	}
	return ""
}

// readDPKG reads the dpkg database, from status, or from distroless images'
// status.d, one file per package.
func readDPKG(r FS, result *Inventory) string {
	var contents strings.Builder
	if data := readFirst(r, result, maxPackageBytes, "/var/lib/dpkg/status"); data != "" {
		contents.WriteString(data)
	} else if entries, err := r.ReadDir("/var/lib/dpkg/status.d"); err == nil {
		for _, e := range entries {
			if !e.IsReg || strings.HasSuffix(e.Name, ".md5sums") {
				continue
			}
			data, _, err := r.ReadFile("/var/lib/dpkg/status.d/"+e.Name, 1<<20)
			if err == nil {
				contents.Write(bytes.TrimSpace(data))
				// distroless omits the Status field: these packages are installed.
				if !bytes.Contains(data, []byte("\nStatus:")) && !bytes.HasPrefix(data, []byte("Status:")) {
					contents.WriteString("\nStatus: install ok installed")
				}
				contents.WriteString("\n\n")
			}
		}
	}
	packages, err := inventory.ParseDPKGStatus(contents.String())
	if err != nil {
		return ""
	}
	return compactDPKG(packages)
}

func compactDPKG(packages []inventory.Package) string {
	var b strings.Builder
	for _, p := range packages {
		fmt.Fprintf(&b, "Package: %s\nStatus: install ok installed\nVersion: %s\nSource: %s\nArchitecture: %s\n\n", p.Name, p.Version, p.Source, p.Arch)
	}
	return b.String()
}

func compactAPK(packages []inventory.Package) string {
	var b strings.Builder
	for _, p := range packages {
		fmt.Fprintf(&b, "P:%s\nV:%s\nA:%s\no:%s\n\n", p.Name, p.Version, p.Arch, p.Source)
	}
	return b.String()
}
