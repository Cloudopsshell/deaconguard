package containers

import (
	"bytes"
	"strings"
	"time"

	"deaconguard/internal/libraries"
)

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

// walkLibraries finds the application libraries in a container, with the
// same files and limits as the host's library check, on the container's own
// file system only (volumes mounted into it are left out, like find -xdev).
func walkLibraries(r *root) libraries.Result {
	var records bytes.Buffer
	files, dirs, total := 0, 0, 0
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
		entries, err := r.readDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			path := strings.TrimSuffix(dir, "/") + "/" + e.name
			if e.dev != r.dev {
				continue
			}
			if e.isDir {
				// A project's node_modules is listed by its lock file; only the
				// global lib/node_modules (packages installed with npm -g) is walked.
				if skipped[path] || e.name == ".git" || (e.name == "node_modules" && !strings.HasSuffix(dir, "/lib")) ||
					strings.Contains(dir, "/node_modules/") && e.name == "node_modules" {
					continue
				}
				walk(path)
				continue
			}
			if !e.isReg || e.size > libraries.MaxFileBytes || !wanted(path, e.name) {
				continue
			}
			if files >= libraries.MaxFiles || total > libraries.MaxOutputBytes {
				stopped = "more than 5,000 package-manager files; the rest weren't read"
				return
			}
			data, _, err := r.readFile(path, libraries.MaxFileBytes)
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
