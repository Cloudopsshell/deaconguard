package containers

import (
	"bytes"
	"strings"
	"time"

	"deaconguard/internal/gobinary"
	"deaconguard/internal/libraries"
)

// maxGoPrograms bounds the Go programs read in one container or image.
const maxGoPrograms = 5000

// lockFiles are the package-manager files read wherever they are, as the
// host's library check reads them (libraries.CollectCommand).
var lockFiles = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"requirements.txt": true, "poetry.lock": true, "Pipfile.lock": true, "go.mod": true,
	"Gemfile.lock": true, "Cargo.lock": true, "composer.lock": true,
}

// skipped are directories not walked: kernel and device file systems, and
// the distribution's own library folders, which the container's package
// check covers.
var skipped = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
	"/usr/lib": true, "/usr/lib32": true, "/usr/lib64": true, "/usr/libexec": true, "/usr/share": true,
}

// SkippedDir reports whether the library walk leaves out the directory name
// in dir: kernel and device file systems, the distribution's own library
// folders, .git, and a project's node_modules, which its lock file lists.
// Only the global lib/node_modules (packages installed with npm -g) is walked.
func SkippedDir(dir, name string) bool {
	path := strings.TrimSuffix(dir, "/") + "/" + name
	return skipped[path] || name == ".git" || (name == "node_modules" && !strings.HasSuffix(dir, "/lib")) ||
		strings.Contains(dir, "/node_modules/") && name == "node_modules"
}

// walkLibraries finds the application libraries in a container, with the
// same files and limits as the host's library check, on the container's own
// file system only (volumes mounted into it are left out, like find -xdev).
func walkLibraries(r FS, packaged bool) libraries.Result {
	var records bytes.Buffer
	files, dirs, total, goPrograms := 0, 0, 0, 0
	deadline := time.Now().Add(walkTimeout)
	stopped := ""
	var walk func(dir string)
	walk = func(dir string) {
		if stopped != "" {
			return
		}
		dirs++
		if dirs > maxWalkDirs || time.Now().After(deadline) {
			stopped = "the container has too many files to walk; some libraries may be missing"
			return
		}
		entries, err := r.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			path := strings.TrimSuffix(dir, "/") + "/" + e.Name
			if e.Dev != r.Device() {
				continue
			}
			if e.IsDir {
				if SkippedDir(dir, e.Name) {
					continue
				}
				walk(path)
				continue
			}
			// A compiled Go program: its build information, outside the
			// distribution's folders when the image has a package database.
			if goReader, ok := r.(GoBinaryReader); ok && e.IsReg && e.Exec && !wanted(path, e.Name) {
				if (packaged && gobinary.DistroDir(path)) || goPrograms >= maxGoPrograms {
					continue
				}
				if record, err := goReader.ReadGoBinary(path); err == nil {
					goPrograms++
					records.WriteByte(0x1e)
					records.WriteString(path)
					records.WriteByte('\n')
					records.Write(record)
					records.WriteByte('\n')
				}
				continue
			}
			if !e.IsReg || e.Size > libraries.MaxFileBytes || !wanted(path, e.Name) {
				continue
			}
			if files >= libraries.MaxFiles || total > libraries.MaxOutputBytes {
				stopped = "more than 5,000 package-manager files; the rest weren't read"
				return
			}
			data, _, err := r.ReadFile(path, libraries.MaxFileBytes)
			if err != nil {
				continue
			}
			files++
			total += len(data)
			records.WriteByte(0x1e)
			records.WriteString(path)
			records.WriteByte('\n')
			records.Write(data)
			records.WriteByte('\n')
		}
	}
	walk("/")
	found := libraries.Parse(records.Bytes())
	if stopped != "" {
		found.Notes = append(found.Notes, stopped)
	}
	return found
}

// wanted reports whether a file is one the library check reads.
func wanted(path, name string) bool {
	if lockFiles[name] {
		return true
	}
	parent := path[:strings.LastIndex(path, "/")]
	grandparent := parent[:max(strings.LastIndex(parent, "/"), 0)]
	switch name {
	case "METADATA":
		return strings.HasSuffix(parent, ".dist-info") && strings.HasSuffix(grandparent, "-packages")
	case "PKG-INFO":
		return strings.HasSuffix(parent, ".egg-info") && strings.HasSuffix(grandparent, "-packages")
	case "package.json":
		// A globally installed npm package: lib/node_modules/name or
		// lib/node_modules/@scope/name.
		_, rest, found := strings.Cut(path, "/lib/node_modules/")
		if !found || strings.Contains(rest, "node_modules") {
			return false
		}
		segments := strings.Count(rest, "/")
		return segments == 1 || (segments == 2 && strings.HasPrefix(rest, "@"))
	}
	return false
}

// LibraryFile reports whether a file at an absolute path in a container or
// image is one the library check reads, by the same rules as the walk:
// not under a skipped directory, a .git folder, or a project's node_modules.
func LibraryFile(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dir := ""
	for _, part := range parts[:len(parts)-1] {
		next := dir + "/" + part
		if skipped[next] || part == ".git" || (part == "node_modules" && !strings.HasSuffix(dir, "/lib")) ||
			(part == "node_modules" && strings.Contains(dir, "/node_modules/")) {
			return false
		}
		dir = next
	}
	return wanted(path, parts[len(parts)-1])
}

// PackageFiles are the files ReadFS reads for the OS packages, besides
// distroless images' /var/lib/dpkg/status.d/*.
var PackageFiles = []string{
	"/etc/os-release", "/usr/lib/os-release",
	"/var/lib/dpkg/status", "/lib/apk/db/installed",
	"/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/Packages.db",
}
