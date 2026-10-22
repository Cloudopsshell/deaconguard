// Package containers finds the containers on a machine (Docker,
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
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// ListCommand lists the containers, running and stopped, one per line:
// PID|ID|name|image|image ID|runtime|state|created|started|finished|exit
// code|restarts|user|privileged|network|ports|command, with the command
// last since it may hold "|". A stopped container's PID is 0. Each runtime
// is asked only if its command exists; a failure of one doesn't stop the
// others, and an engine whose inspect lacks one of the details falls back
// to the first six fields.
const ListCommand = `{ command -v docker >/dev/null 2>&1 && docker ps -a --no-trunc --format '{{.ID}}' 2>/dev/null | head -n 300 | while read -r id; do ` +
	`docker inspect --format '` + dockerDetails + `|docker|` + engineDetails + `' "$id" 2>/dev/null || { echo; ` +
	`docker inspect --format '` + dockerDetails + `|docker' "$id" 2>/dev/null; }; done; } ; ` +
	`{ command -v podman >/dev/null 2>&1 && podman ps -a --no-trunc --format '{{.ID}}' 2>/dev/null | head -n 300 | while read -r id; do ` +
	`podman inspect --format '` + podmanDetails + `|podman|` + engineDetails + `' "$id" 2>/dev/null || { echo; ` +
	`podman inspect --format '` + podmanDetails + `|podman' "$id" 2>/dev/null; }; done; } ; ` +
	`{ command -v crictl >/dev/null 2>&1 && crictl ps -a -q 2>/dev/null | head -n 300 | while read -r id; do ` +
	`{ crictl inspect -o go-template --template '` + criDetails + `|cri|` + criMore + `' "$id" 2>/dev/null || { echo; ` +
	`crictl inspect -o go-template --template '` + criDetails + `|cri' "$id" 2>/dev/null; }; }; echo; done; } ; true`

const (
	dockerDetails = `{{.State.Pid}}|{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.Image}}`
	podmanDetails = `{{.State.Pid}}|{{.Id}}|{{.Name}}|{{.ImageName}}|{{.Image}}`
	// engineDetails are the same in Docker's and Podman's inspect.
	engineDetails = `{{.State.Status}}|{{.Created}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.ExitCode}}|{{.RestartCount}}|` +
		`{{.Config.User}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|` +
		`{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}|` +
		`{{json .Config.Entrypoint}} {{json .Config.Cmd}}`
	criDetails = `{{.info.pid}}|{{.status.id}}|{{index .status.labels "io.kubernetes.pod.namespace"}}/{{index .status.labels "io.kubernetes.pod.name"}}/{{.status.metadata.name}}|{{.status.image.image}}|{{.status.imageRef}}`
	// criMore: the pod's network and the command aren't in a CRI
	// container's status; the restart count is its attempt.
	criMore = `{{.status.state}}|{{.status.createdAt}}|{{.status.startedAt}}|{{.status.finishedAt}}|{{.status.exitCode}}|{{.status.metadata.attempt}}|||||`
)

// Container is one container on a machine.
type Container struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"image_id"`
	Runtime string `json:"runtime"`
	// State is running, paused, restarting, exited, created or dead; empty
	// from agents before 1.8.0, which listed running containers only.
	State      string `json:"state,omitempty"`
	Created    string `json:"created,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Restarts   int    `json:"restarts,omitempty"`
	// User is the user the container was configured with; empty is root.
	User       string   `json:"user,omitempty"`
	Privileged bool     `json:"privileged,omitempty"`
	Network    string   `json:"network,omitempty"`
	Ports      []string `json:"ports,omitempty"`
	Command    string   `json:"command,omitempty"`
	// RunsAs is the user its main process runs as, read from /proc.
	RunsAs string `json:"runs_as,omitempty"`
	pid    int
}

// Running reports whether the container has a process whose files can be
// read.
func (c Container) Running() bool { return c.pid > 0 }

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

// ParseList reads ListCommand's output. Repeats, such as a Podman
// container that the docker command (podman-docker) lists too, are
// skipped. Running containers come first, then by name.
func ParseList(output []byte) []Container {
	var list []Container
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) < 6 || fields[1] == "" || fields[1] == noValue {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			pid = 0
		}
		if pid < 0 || seen[fields[1]] {
			continue
		}
		seen[fields[1]] = true
		name := strings.TrimPrefix(fields[2], "/")
		if fields[5] == "cri" {
			name = strings.TrimPrefix(name, "/")
		}
		container := Container{ID: fields[1], Name: name, Image: fields[3], ImageID: fields[4], Runtime: fields[5], pid: pid}
		if len(fields) >= 17 {
			detail := func(i int) string {
				if value := strings.TrimSpace(fields[i]); value != noValue {
					return value
				}
				return ""
			}
			container.State = normalState(detail(6))
			container.Created, container.StartedAt, container.FinishedAt = timestamp(detail(7)), timestamp(detail(8)), timestamp(detail(9))
			container.ExitCode, _ = strconv.Atoi(detail(10))
			container.Restarts, _ = strconv.Atoi(detail(11))
			container.User = detail(12)
			container.Privileged = detail(13) == "true"
			container.Network = detail(14)
			container.Ports = strings.Fields(detail(15))
			container.Command = command(strings.Join(fields[16:], "|"))
		} else if pid > 0 {
			container.State = "running"
		} else {
			container.State = "stopped"
		}
		if container.State == "running" && pid == 0 {
			container.State = "exited"
		}
		if container.State == "running" {
			container.FinishedAt = ""
		}
		list = append(list, container)
		if len(list) >= MaxContainers {
			break
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Running() != list[j].Running() {
			return list[i].Running()
		}
		return list[i].Name < list[j].Name
	})
	return list
}

// noValue is what a Go template prints for a missing map key, as crictl's
// output has for fields a runtime leaves out.
const noValue = "<no value>"

// normalState gives CRI's states (CONTAINER_RUNNING) Docker's names.
func normalState(state string) string {
	state = strings.ToLower(strings.TrimPrefix(state, "CONTAINER_"))
	if state == "unknown" {
		return ""
	}
	return state
}

// timestamp reads the times Docker (RFC 3339), Podman (Go's time format)
// and crictl print, as RFC 3339 in UTC; a zero time is empty.
func timestamp(value string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999 -0700 -0700"} {
		if t, err := time.Parse(layout, value); err == nil {
			if t.Year() <= 1970 {
				return ""
			}
			return t.UTC().Format(time.RFC3339)
		}
	}
	if nanos, err := strconv.ParseInt(value, 10, 64); err == nil && nanos > 0 {
		return time.Unix(0, nanos).UTC().Format(time.RFC3339)
	}
	return ""
}

// command joins the entrypoint and command Docker and Podman print as JSON
// (Podman 4 prints the entrypoint as a string).
func command(value string) string {
	var parts []string
	decoder := json.NewDecoder(strings.NewReader(value))
	for {
		var part any
		if err := decoder.Decode(&part); err != nil {
			break
		}
		switch v := part.(type) {
		case string:
			parts = append(parts, v)
		case []any:
			for _, arg := range v {
				if s, ok := arg.(string); ok {
					parts = append(parts, s)
				}
			}
		}
	}
	joined := strings.Join(parts, " ")
	if len(joined) > 500 {
		joined = joined[:500] + "…"
	}
	return joined
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
	result = ReadFS(r, container)
	result.RunsAs = runsAs(container.pid, r)
	return result
}

// runsAs names the user the container's main process runs as: its
// effective user ID from /proc, named from the container's /etc/passwd.
func runsAs(pid int, r FS) string {
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if hostRoot := local.HostRoot(); err != nil && hostRoot != "" {
		status, err = os.ReadFile(filepath.Join(hostRoot, "proc", strconv.Itoa(pid), "status"))
	}
	if err != nil {
		return ""
	}
	uid := ""
	for _, line := range strings.Split(string(status), "\n") {
		if fields := strings.Fields(line); len(fields) >= 3 && fields[0] == "Uid:" {
			uid = fields[2]
		}
	}
	if uid == "" {
		return ""
	}
	if uid == "0" {
		return "root"
	}
	if passwd, _, err := r.ReadFile("/etc/passwd", 1<<20); err == nil {
		for _, line := range strings.Split(string(passwd), "\n") {
			if fields := strings.Split(line, ":"); len(fields) > 2 && fields[2] == uid && fields[0] != "" {
				return fields[0] + " (uid " + uid + ")"
			}
		}
	}
	return "uid " + uid
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
