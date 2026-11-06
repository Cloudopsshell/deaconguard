package live

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Container is what the agent learns about the container a process runs
// in. Namespace and Pod are set for a Kubernetes pod's container.
type Container struct {
	Name      string
	Image     string
	Namespace string
	Pod       string
}

// ContainerLookup asks the machine's container runtime about one
// container, by its full ID. It returns found false when no runtime knows
// it.
type ContainerLookup func(id string) (container Container, found bool, err error)

// containerOf finds the container a process runs in from its cgroup, as
// /proc/PID/cgroup lists it: the innermost path component that names a
// 64-character container ID, as Docker, Podman, containerd and CRI-O name
// their cgroups. It returns "" for a process outside any container.
func containerOf(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		// hierarchy:controllers:path; cgroup v2 has one line, v1 several
		// naming the same container.
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		components := strings.Split(parts[2], "/")
		for i := len(components) - 1; i >= 0; i-- {
			if id := containerIDIn(components[i]); id != "" {
				return id
			}
		}
	}
	return ""
}

// containerIDIn reads a container ID from one cgroup path component, such
// as docker-ID.scope, cri-containerd-ID.scope, crio-ID.scope, libpod-ID.scope
// or the bare ID cgroupfs drivers use.
func containerIDIn(component string) string {
	component = strings.TrimSuffix(component, ".scope")
	if dash := strings.LastIndexByte(component, '-'); dash >= 0 {
		component = component[dash+1:]
	}
	if len(component) != 64 {
		return ""
	}
	for _, c := range component {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return ""
		}
	}
	return component
}

// Limits on what the agent remembers about containers.
const (
	// containerKnown is how long a container's name is remembered, and
	// containerUnknown how long until a container no runtime knew, or a
	// failed lookup, is asked about again.
	containerKnown   = time.Hour
	containerUnknown = 5 * time.Minute
	maxContainers    = 512
)

type containerEntry struct {
	at        time.Time
	found     bool
	container Container
}

// containerNames remembers the containers looked up, so each is asked
// about once however many alerts it raises.
type containerNames struct {
	mu      sync.Mutex
	lookup  ContainerLookup
	entries map[string]containerEntry
}

func (c *containerNames) setLookup(lookup ContainerLookup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookup = lookup
}

// name returns what is known about the container with this ID, asking the
// runtime when it's new.
func (c *containerNames) name(id string, now time.Time) (Container, bool) {
	c.mu.Lock()
	entry, ok := c.entries[id]
	lookup := c.lookup
	c.mu.Unlock()
	if ok && (entry.found && now.Sub(entry.at) < containerKnown || !entry.found && now.Sub(entry.at) < containerUnknown) {
		return entry.container, entry.found
	}
	if lookup == nil {
		return Container{}, false
	}
	container, found, err := lookup(id)
	entry = containerEntry{at: now, found: found && err == nil, container: container}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]containerEntry{}
	}
	if len(c.entries) >= maxContainers {
		for key, old := range c.entries {
			if now.Sub(old.at) >= containerUnknown {
				delete(c.entries, key)
			}
		}
		if len(c.entries) >= maxContainers {
			c.entries = map[string]containerEntry{}
		}
	}
	c.entries[id] = entry
	return entry.container, entry.found
}

// cached fills in the alert's container from what is already known,
// without asking the runtime.
func (c *containerNames) cached(alert *Alert, now time.Time) {
	if alert.ContainerID == "" || alert.Container != "" {
		return
	}
	c.mu.Lock()
	entry, ok := c.entries[alert.ContainerID]
	c.mu.Unlock()
	if ok && entry.found && now.Sub(entry.at) < containerKnown {
		alert.Container, alert.Image = entry.container.Name, entry.container.Image
		alert.Namespace, alert.Pod = entry.container.Namespace, entry.container.Pod
	}
}

// inContainers notes which container the event's process runs in, for its
// alerts: by the event's cgroup ID, or else from /proc while the process
// still runs.
func inContainers(event Event, alerts []Alert, machine Machine, index *cgroupIndex, now time.Time) {
	if len(alerts) == 0 {
		return
	}
	container, known := "", false
	if index != nil {
		container, known = index.container(event.Cgroup, now)
	}
	for i := range alerts {
		if alerts[i].Test {
			continue
		}
		if !known && alerts[i].PID != 0 {
			container = containerOf(machine.Cgroup(alerts[i].PID))
		}
		alerts[i].ContainerID = container
	}
}

// describe fills in the container names of alerts that came from
// containers.
func (c *containerNames) describe(alerts []Alert, now time.Time) {
	for i := range alerts {
		if alerts[i].ContainerID == "" || alerts[i].Container != "" {
			continue
		}
		if container, found := c.name(alerts[i].ContainerID, now); found {
			alerts[i].Container = container.Name
			alerts[i].Image = container.Image
			alerts[i].Namespace = container.Namespace
			alerts[i].Pod = container.Pod
		}
	}
}

// Limits on finding containers by cgroup ID.
const (
	// cgroupRebuild is how often, at most, the cgroup tree is walked again
	// for an ID it didn't hold.
	cgroupRebuild = 30 * time.Second
	// maxCgroupDirs bounds one walk.
	maxCgroupDirs = 50000
)

// cgroupIndex finds the container a kernel cgroup ID belongs to. The
// watchers record each event's cgroup ID, which, unlike the process ID,
// is the same in every process namespace and still names the container
// after a short-lived program exits. In cgroup v2 the ID is the inode of
// the cgroup's directory, so a walk of the tree maps IDs to the container
// IDs in their paths.
type cgroupIndex struct {
	roots []string
	// inode reads a directory's inode, which is its cgroup ID.
	inode func(path string) uint64

	mu      sync.Mutex
	byID    map[uint64]string
	builtAt time.Time
}

func newCgroupIndex(hostRoot string, inode func(string) uint64) *cgroupIndex {
	roots := []string{}
	if hostRoot != "" && hostRoot != "/" {
		// In Kubernetes the node's tree, when its root is mounted.
		roots = append(roots, filepath.Join(hostRoot, "sys/fs/cgroup"))
	}
	roots = append(roots, "/sys/fs/cgroup")
	return &cgroupIndex{roots: roots, inode: inode}
}

// container returns the container ID for a cgroup ID, if the tree holds
// it. Cgroups outside containers, and ones too new for the last walk,
// aren't found; the caller then asks /proc.
func (c *cgroupIndex) container(id uint64, now time.Time) (string, bool) {
	if id == 0 || c.inode == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if container, ok := c.byID[id]; ok {
		return container, true
	}
	if c.byID != nil && now.Sub(c.builtAt) < cgroupRebuild {
		return "", false
	}
	c.build(now)
	container, ok := c.byID[id]
	return container, ok
}

// build walks the first root that is a cgroup v2 tree. Every directory
// under a container's own cgroup belongs to it too. The caller holds c.mu.
func (c *cgroupIndex) build(now time.Time) {
	c.byID, c.builtAt = map[uint64]string{}, now
	for _, root := range c.roots {
		if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
			continue
		}
		seen := 0
		var walk func(dir, container string)
		walk = func(dir, container string) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return
			}
			for _, entry := range entries {
				if !entry.IsDir() || seen >= maxCgroupDirs {
					continue
				}
				seen++
				path := filepath.Join(dir, entry.Name())
				owner := container
				if id := containerIDIn(entry.Name()); id != "" {
					owner = id
				}
				if owner != "" {
					if inode := c.inode(path); inode != 0 {
						c.byID[inode] = owner
					}
				}
				walk(path, owner)
			}
		}
		walk(root, "")
		return
	}
}
