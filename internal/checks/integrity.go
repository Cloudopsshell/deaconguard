package checks

import (
	"fmt"
	"strings"
	"time"

	"deaconguard/internal/platform"
)

const (
	integrityTimeout = 20 * time.Minute
	integrityLimit   = 16 << 20
)

// Directories whose packaged files are executed or loaded; a changed file
// here is how userland rootkits and trojaned tools usually appear.
var executableDirectories = []string{
	"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
	"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/boot/",
}

type verifyEntry struct {
	flags    string
	conffile bool
	missing  bool
	path     string
}

func runIntegrity(executor *Executor, target platform.Platform) Result {
	command := "rpm -Va --nodeps --noscripts --nomtime"
	if target.Family == platform.Ubuntu || target.Family == platform.Debian {
		command = "dpkg --verify"
	}
	output, code, privileged, err := executor.RunPrivileged(command, integrityLimit, integrityTimeout)
	// Both tools exit non-zero when they find differences; only a failure
	// without output means the check did not run.
	if err != nil && (code < 0 || len(output) == 0) {
		return failed(fmt.Errorf("%s: %w", command, err))
	}
	result := evaluateIntegrity(parseVerify(output))
	result.Privileged = privileged
	return result
}

// parseVerify reads rpm -V and dpkg --verify output, which share a layout:
// nine attribute flags or "missing", a space, a file-type marker such as 'c'
// for configuration files, a space, and the path.
func parseVerify(output []byte) []verifyEntry {
	entries := make([]verifyEntry, 0)
	for _, line := range lines(output) {
		var entry verifyEntry
		rest := line
		if strings.HasPrefix(line, "missing") {
			entry.missing = true
			rest = strings.TrimLeft(strings.TrimPrefix(line, "missing"), " ")
		} else {
			if len(line) < 12 {
				continue
			}
			entry.flags = line[:9]
			rest = strings.TrimLeft(line[9:], " ")
			if len(line) > 11 && line[10] != ' ' && line[11] == ' ' {
				rest = line[10:]
			}
		}
		if len(rest) > 2 && rest[1] == ' ' && strings.ContainsRune("cdglr", rune(rest[0])) {
			entry.conffile = rest[0] == 'c'
			rest = rest[2:]
		}
		entry.path = strings.TrimSpace(rest)
		if strings.HasPrefix(entry.path, "/") {
			entries = append(entries, entry)
		}
	}
	return entries
}

func evaluateIntegrity(entries []verifyEntry) Result {
	var result Result
	changedConfig, unverifiable, missingOther := 0, 0, 0
	for _, entry := range entries {
		executable := inExecutableDirectory(entry.path)
		switch {
		case entry.conffile:
			changedConfig++
		case entry.missing && executable:
			result.add(Finding{
				Rule: "integrity.missing-file", Severity: "LOW", Title: "Packaged program file is missing",
				Detail:   "A file installed by a package is no longer present. This is usually a manual deletion, but can hide a replaced tool.",
				Evidence: entry.path,
			})
		case entry.missing:
			missingOther++
		case len(entry.flags) > 2 && entry.flags[2] == '5' && executable:
			result.add(Finding{
				Rule: "integrity.modified-binary", Severity: "HIGH", Title: "System binary or library differs from its package",
				Detail:   "The file's checksum no longer matches the package. Replaced system tools and libraries are a common sign of a rootkit; reinstall the package and investigate if this was not an intentional change.",
				Evidence: entry.path,
			})
		case len(entry.flags) > 2 && entry.flags[2] == '5':
			result.add(Finding{
				Rule: "integrity.modified-file", Severity: "MEDIUM", Title: "Packaged file differs from its package",
				Detail:   "The file's checksum no longer matches the package that installed it.",
				Evidence: entry.path,
			})
		case len(entry.flags) > 2 && entry.flags[2] == '?':
			unverifiable++
		case len(entry.flags) > 1 && entry.flags[1] == 'M' && executable:
			result.add(Finding{
				Rule: "integrity.changed-permissions", Severity: "MEDIUM", Title: "Permissions changed on a system binary",
				Detail:   "The file mode differs from the package. An added setuid bit or write permission can be used to escalate privileges.",
				Evidence: entry.flags + " " + entry.path,
			})
		}
	}
	if changedConfig > 0 {
		result.note("%d configuration files differ from their package defaults; this is usually intentional and is not reported.", changedConfig)
	}
	if missingOther > 0 {
		result.note("%d packaged documentation or data files are missing; minimal images often omit them.", missingOther)
	}
	if unverifiable > 0 {
		result.note("%d files could not be read to verify their checksum. Turn on \"use sudo\" for this host to verify them.", unverifiable)
	}
	return result.finish(unverifiable > 0)
}

func inExecutableDirectory(path string) bool {
	for _, directory := range executableDirectories {
		if strings.HasPrefix(path, directory) {
			return true
		}
	}
	return false
}
