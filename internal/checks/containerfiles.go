package checks

import (
	"fmt"
	"path"
	"strings"

	"deaconguard/internal/containers"
)

// The malware checks also look at each running container's own files: its
// writable layer and emptyDir volumes (containers.FindWritable). The
// scanners are given those folders on the host as starting points, and
// never follow a link inside them, so a container can't point one at the
// host's files. The image's layers are left out: they are the same in every
// container of the image, and nothing written at runtime is in them.

// containerFolders lists the folders to scan, one per line, for a
// command's standard input, and how many containers they belong to.
func containerFolders(list []containers.Writable) (string, int) {
	var out strings.Builder
	count := 0
	for _, container := range list {
		if len(container.Dirs) == 0 {
			continue
		}
		count++
		for _, dir := range container.Dirs {
			out.WriteString(dir.HostPath + "\n")
		}
	}
	return out.String(), count
}

// containerTempFolders lists the temporary folders of the containers, for
// the executable-in-/tmp check: in the writable layer, and the emptyDir
// volumes mounted there.
func containerTempFolders(list []containers.Writable) string {
	var out strings.Builder
	for _, container := range list {
		for _, dir := range container.Dirs {
			for _, temp := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
				switch {
				case dir.Path == "/":
					out.WriteString(dir.HostPath + temp + "\n")
				case dir.Path == temp || strings.HasPrefix(dir.Path, temp+"/"):
					out.WriteString(dir.HostPath + "\n")
				}
			}
		}
	}
	return out.String()
}

// inContainer finds the container a host path is in, and the path inside
// it: the longest matching folder wins, since a volume is mounted inside
// the writable layer's tree.
func inContainer(hostPath string, list []containers.Writable) (name, inside string, found bool) {
	_, name, inside, found = containerOf(hostPath, list)
	return name, inside, found
}

// containerOf is inContainer with the container's ID.
func containerOf(hostPath string, list []containers.Writable) (id, name, inside string, found bool) {
	best := -1
	for _, container := range list {
		for _, dir := range container.Dirs {
			rest, ok := strings.CutPrefix(hostPath, dir.HostPath)
			if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) || len(dir.HostPath) <= best {
				continue
			}
			best = len(dir.HostPath)
			id, name, inside, found = container.ID, container.Name, path.Join(dir.Path, rest), true
		}
	}
	return id, name, inside, found
}

// placeInContainer moves a finding about a host path into its container:
// the container is named in the title (the dashboard shows it in its own
// column) and the evidence is the path inside the container.
func placeInContainer(finding *Finding, hostPath, rest string, list []containers.Writable) {
	id, name, inside, found := containerOf(hostPath, list)
	if !found {
		return
	}
	finding.Container, finding.ContainerID = name, id
	finding.Title = name + ": " + finding.Title
	finding.Evidence = inside + rest
	// The advice is for the container, not the machine.
	finding.Detail = strings.NewReplacer("Isolate the host", "Isolate the container", "isolate the host", "isolate the container").Replace(finding.Detail) +
		" The container wrote this file after it started; it isn't in its image."
}

// containersNote says what of the containers was scanned.
func containersNote(result *Result, list []containers.Writable, skipped int) {
	folders, count := containerFolders(list)
	if count > 0 {
		result.note("Also scanned what %s wrote since starting (%s: writable layers and emptyDir volumes; not the images' own files, nor other volumes).",
			plural(count, "running container", "running containers"), plural(strings.Count(folders, "\n"), "folder", "folders"))
	}
	if skipped > 0 {
		result.note("The writable files of %s could not be found (a storage driver other than overlay), so they were not scanned.",
			plural(skipped, "running container", "running containers"))
	}
}

func plural(count int, one, many string) string {
	if count == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", count, many)
}
