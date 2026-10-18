// Package libraries finds the application libraries installed on a machine,
// from the files package managers leave behind: npm, Yarn and pnpm lock
// files, installed Python packages and Python lock files, Go modules, Ruby
// bundles, Rust crates and Composer packages. The agent collects the files
// with one fixed, read-only command (CollectCommand) and parses them here;
// the server checks the libraries against OSV (internal/osv).
package libraries

import (
	"bytes"
	"sort"
	"strings"
)

// Ecosystems, named as OSV names them.
const (
	NPM       = "npm"
	PyPI      = "PyPI"
	Go        = "Go"
	RubyGems  = "RubyGems"
	CratesIO  = "crates.io"
	Packagist = "Packagist"
)

// Library is one version of one package, with the files it was found in.
type Library struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Paths     []string `json:"paths"`
}

// Limits keep a machine with very many projects from producing an unbounded
// result. Beyond them, the result says it is incomplete.
const (
	MaxFiles       = 5000
	MaxFileBytes   = 4 << 20
	MaxOutputBytes = 64 << 20
	MaxLibraries   = 50000
)

// recordStart begins each file in CollectCommand's output: the byte 0x1e
// (record separator), the path, a newline, then the file's contents.
const recordStart = '\x1e'

// CollectCommand lists the package-manager files on the machine's main file
// systems (missing ones are skipped) and prints each one, at most MaxFileBytes, after a record separator
// and its path. It is a fixed, read-only string: paths are only read, never
// run. Kernel and device file systems, version-control metadata and libraries
// nested inside other libraries' node_modules are skipped, and so are
// /usr/lib*, /usr/libexec and /usr/share: libraries there come from the
// distribution's packages, which the package check covers with the
// distribution's own advisories (OSV doesn't know its back-ported fixes).
// /usr/local is checked.
const CollectCommand = `find / /home /opt /srv /usr/local /var/www /root -xdev ` +
	`\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /usr/lib -o -path /usr/lib32 -o -path /usr/lib64 -o -path /usr/libexec -o -path /usr/share ` +
	`-o -name .git -o -path '*/node_modules/*/node_modules' \) -prune -o -type f ` +
	`\( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml ` +
	`-o -name requirements.txt -o -name poetry.lock -o -name Pipfile.lock -o -path '*-packages/*.dist-info/METADATA' -o -path '*-packages/*.egg-info/PKG-INFO' ` +
	`-o -path '*/lib/node_modules/*/package.json' -o -name go.mod -o -name Gemfile.lock -o -name Cargo.lock -o -name composer.lock \) ` +
	`-size -4097k -print 2>/dev/null | awk '!seen[$0]++' | head -n 5000 | ` +
	`while IFS= read -r file; do printf '\036%s\n' "$file"; head -c 4194304 -- "$file" 2>/dev/null; printf '\n'; done`

// Result is what Parse found.
type Result struct {
	Libraries []Library `json:"libraries"`
	Files     int       `json:"files"`
	// Notes say what couldn't be read, such as a file in an unknown format.
	Notes []string `json:"notes,omitempty"`
}

type key struct{ ecosystem, name, version string }

type collector struct {
	found map[key]map[string]bool
	notes []string
}

func (c *collector) add(ecosystem, name, version, path string) {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if name == "" || version == "" || len(name) > 214 || len(version) > 128 {
		return
	}
	if ecosystem == PyPI {
		name = normalizePythonName(name)
	}
	k := key{ecosystem, name, version}
	if c.found[k] == nil {
		if len(c.found) >= MaxLibraries {
			return
		}
		c.found[k] = make(map[string]bool)
	}
	c.found[k][path] = true
}

// Parse reads CollectCommand's output.
func Parse(output []byte) Result {
	c := &collector{found: make(map[key]map[string]bool)}
	files := 0
	for _, record := range bytes.Split(output, []byte{recordStart}) {
		newline := bytes.IndexByte(record, '\n')
		if newline <= 0 {
			continue
		}
		path := string(record[:newline])
		contents := record[newline+1:]
		files++
		if err := parseFile(c, path, contents); err != nil {
			c.notes = append(c.notes, path+": "+err.Error())
		}
	}
	result := Result{Files: files, Notes: c.notes}
	for k, paths := range c.found {
		library := Library{Ecosystem: k.ecosystem, Name: k.name, Version: k.version}
		for path := range paths {
			library.Paths = append(library.Paths, path)
		}
		sort.Strings(library.Paths)
		result.Libraries = append(result.Libraries, library)
	}
	sort.Slice(result.Libraries, func(i, j int) bool {
		a, b := result.Libraries[i], result.Libraries[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	if len(c.found) >= MaxLibraries {
		result.Notes = append(result.Notes, "more than 50,000 libraries were found; the rest are not listed")
	}
	if len(result.Notes) > 50 {
		result.Notes = append(result.Notes[:50], "more files could not be read")
	}
	return result
}

func parseFile(c *collector, path string, contents []byte) error {
	base := path[strings.LastIndexByte(path, '/')+1:]
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return parseNPMLock(c, path, contents)
	case base == "yarn.lock":
		return parseYarnLock(c, path, contents)
	case base == "pnpm-lock.yaml":
		return parsePNPMLock(c, path, contents)
	case base == "package.json":
		return parseInstalledNPM(c, path, contents)
	case base == "METADATA" || base == "PKG-INFO":
		return parsePythonMetadata(c, path, contents)
	case base == "requirements.txt":
		return parseRequirements(c, path, contents)
	case base == "poetry.lock" || base == "Cargo.lock":
		return parseTOMLPackages(c, path, contents)
	case base == "Pipfile.lock":
		return parsePipfileLock(c, path, contents)
	case base == "go.mod":
		return parseGoMod(c, path, contents)
	case base == "Gemfile.lock":
		return parseGemfileLock(c, path, contents)
	case base == "composer.lock":
		return parseComposerLock(c, path, contents)
	}
	return nil
}

// normalizePythonName follows PEP 503: lower case, runs of -, _ and . as one -.
func normalizePythonName(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !dash {
				b.WriteByte('-')
			}
			dash = true
			continue
		}
		dash = false
		b.WriteRune(r)
	}
	return b.String()
}
