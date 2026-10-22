package libraries

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// package-lock.json and npm-shrinkwrap.json: lockfileVersion 2 and 3 list
// every installed package under "packages", keyed by its path; version 1
// nests them under "dependencies".
func parseNPMLock(c *collector, path string, contents []byte) error {
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]npmV1Dependency `json:"dependencies"`
	}
	if err := json.Unmarshal(contents, &lock); err != nil {
		return fmt.Errorf("not a valid npm lock file: %w", err)
	}
	if len(lock.Packages) > 0 {
		for location, entry := range lock.Packages {
			if location == "" || entry.Link {
				continue // "" is the project itself
			}
			name := entry.Name
			if index := strings.LastIndex(location, "node_modules/"); index >= 0 {
				name = location[index+len("node_modules/"):]
			}
			if name == "" || isNonRegistryVersion(entry.Version) {
				continue
			}
			c.add(NPM, name, entry.Version, path)
		}
		return nil
	}
	var walk func(map[string]npmV1Dependency)
	walk = func(dependencies map[string]npmV1Dependency) {
		for name, dependency := range dependencies {
			if !isNonRegistryVersion(dependency.Version) {
				c.add(NPM, name, dependency.Version, path)
			}
			walk(dependency.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return nil
}

type npmV1Dependency struct {
	Version      string                     `json:"version"`
	Dependencies map[string]npmV1Dependency `json:"dependencies"`
}

// isNonRegistryVersion is true for dependencies from git, a file or a URL,
// which OSV can't match by version.
func isNonRegistryVersion(version string) bool {
	return version == "" || strings.Contains(version, ":") || strings.HasPrefix(version, "/")
}

// yarn.lock (Yarn 1 and Berry): entries start at column 0 with one or more
// "name@range" specifiers and have an indented `version` line.
func parseYarnLock(c *collector, path string, contents []byte) error {
	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") {
			names = names[:0]
			for _, specifier := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				specifier = strings.Trim(strings.TrimSpace(specifier), `"`)
				if name := yarnName(specifier); name != "" {
					names = append(names, name)
				}
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:") {
			version := strings.Trim(strings.TrimSpace(strings.TrimLeft(strings.TrimPrefix(trimmed, "version"), ": ")), `"`)
			if len(names) > 0 {
				c.add(NPM, names[0], version, path)
			}
			names = names[:0]
		}
	}
	return scanner.Err()
}

// yarnName takes the package name from "name@range", "@scope/name@range" or
// "name@npm:range"; other protocols (git, file, workspace, patch) are skipped.
func yarnName(specifier string) string {
	at := strings.LastIndex(specifier, "@")
	if at <= 0 {
		return ""
	}
	name, rangePart := specifier[:at], specifier[at+1:]
	if strings.HasPrefix(name, "@") && !strings.Contains(name, "/") {
		return ""
	}
	if index := strings.Index(rangePart, ":"); index >= 0 && !strings.HasPrefix(rangePart, "npm:") {
		return ""
	}
	if index := strings.Index(name, "@npm:"); index >= 0 {
		name = name[:index]
	}
	if strings.Contains(name, "@patch:") || strings.Contains(name, "@workspace:") {
		return ""
	}
	return name
}

// pnpm-lock.yaml: "packages" is keyed "/name@version" (lockfile 6) or
// "name@version" (9), possibly followed by "(peer@x)" suffixes.
func parsePNPMLock(c *collector, path string, contents []byte) error {
	var lock struct {
		Packages map[string]any `yaml:"packages"`
	}
	if err := yaml.Unmarshal(contents, &lock); err != nil {
		return fmt.Errorf("not a valid pnpm lock file: %w", err)
	}
	for specifier := range lock.Packages {
		specifier = strings.TrimPrefix(specifier, "/")
		if index := strings.IndexByte(specifier, '('); index > 0 {
			specifier = specifier[:index]
		}
		at := strings.LastIndex(specifier, "@")
		if at <= 0 {
			// lockfile 5: "/name/1.2.3"
			slash := strings.LastIndex(specifier, "/")
			if slash <= 0 {
				continue
			}
			c.add(NPM, specifier[:slash], specifier[slash+1:], path)
			continue
		}
		version := specifier[at+1:]
		if isNonRegistryVersion(version) {
			continue
		}
		c.add(NPM, specifier[:at], version, path)
	}
	return nil
}

// A globally installed npm package: lib/node_modules/<name>/package.json.
func parseInstalledNPM(c *collector, path string, contents []byte) error {
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return fmt.Errorf("not a valid package.json: %w", err)
	}
	c.add(NPM, manifest.Name, manifest.Version, path)
	return nil
}

// An installed Python package: site-packages/<name>.dist-info/METADATA, or
// PKG-INFO in an .egg-info folder; both start with the same headers.
func parsePythonMetadata(c *collector, path string, contents []byte) error {
	var name, version string
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // headers end at the first blank line
		}
		if value, ok := strings.CutPrefix(line, "Name:"); ok {
			name = value
		} else if value, ok := strings.CutPrefix(line, "Version:"); ok {
			version = value
		}
	}
	if name == "" || version == "" {
		return errors.New("no Name and Version in the package metadata")
	}
	c.add(PyPI, name, version, path)
	return nil
}

var pinnedRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:;.*)?$`)

// requirements.txt: only exact pins (name==1.2.3) name a version.
func parseRequirements(c *collector, path string, contents []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if index := strings.Index(line, " #"); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\\"))
		if index := strings.Index(line, " --hash"); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if match := pinnedRequirement.FindStringSubmatch(line); match != nil {
			c.add(PyPI, match[1], match[2], path)
		}
	}
	return scanner.Err()
}

// poetry.lock and Cargo.lock: [[package]] tables with name and version keys.
// Cargo packages from git or a path have a source other than crates.io.
func parseTOMLPackages(c *collector, path string, contents []byte) error {
	ecosystem := PyPI
	if strings.HasSuffix(path, "Cargo.lock") {
		ecosystem = CratesIO
	}
	var name, version, source string
	inPackage := false
	flush := func() {
		if inPackage && (ecosystem != CratesIO || source == "" || strings.HasPrefix(source, "registry+")) {
			c.add(ecosystem, name, version, path)
		}
		name, version, source = "", "", ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			flush()
			inPackage = line == "[[package]]"
			continue
		}
		if !inPackage {
			continue
		}
		keyName, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(keyName) {
		case "name":
			name = value
		case "version":
			version = value
		case "source":
			source = value
		}
	}
	flush()
	return scanner.Err()
}

// Pipfile.lock: "default" and "develop" map names to {"version": "==1.2.3"}.
func parsePipfileLock(c *collector, path string, contents []byte) error {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(contents, &lock); err != nil {
		return fmt.Errorf("not a valid Pipfile.lock: %w", err)
	}
	for _, section := range []string{"default", "develop"} {
		var packages map[string]struct {
			Version string `json:"version"`
		}
		if raw, ok := lock[section]; ok {
			if err := json.Unmarshal(raw, &packages); err != nil {
				return fmt.Errorf("not a valid Pipfile.lock: %w", err)
			}
		}
		for name, entry := range packages {
			if version, ok := strings.CutPrefix(entry.Version, "=="); ok {
				c.add(PyPI, name, version, path)
			}
		}
	}
	return nil
}

// parseGoBinary reads a compiled Go program's record (gobinary.Record):
// "stdlib" with its Go version, then its modules, one "path<TAB>version" per
// line.
func parseGoBinary(c *collector, path string, record []byte) {
	for _, line := range strings.Split(string(record), "\n") {
		if name, version, found := strings.Cut(line, "\t"); found {
			c.add(Go, name, version, path)
		}
	}
}

// go.mod: require lines and blocks. The module's own path is not a library.
func parseGoMod(c *collector, path string, contents []byte) error {
	inBlock := false
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if index := strings.Index(line, "//"); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
			continue
		case fields[0] == "require" && len(fields) >= 2 && fields[1] == "(":
			inBlock = true
			continue
		case inBlock && fields[0] == ")":
			inBlock = false
			continue
		case fields[0] == "require" && len(fields) >= 3:
			fields = fields[1:]
		case !inBlock:
			continue
		}
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "v") {
			c.add(Go, fields[0], fields[1], path)
		}
	}
	return scanner.Err()
}

var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9][A-Za-z0-9._-]*) \(([0-9][^)\s]*)\)$`)

// Gemfile.lock: gems are listed as "    name (version)" under GEM's "specs:".
func parseGemfileLock(c *collector, path string, contents []byte) error {
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" && line[0] != ' ' {
			section = strings.TrimSpace(line)
			continue
		}
		if section != "GEM" {
			continue
		}
		if match := gemSpec.FindStringSubmatch(line); match != nil {
			version := match[2]
			if index := strings.IndexByte(version, '-'); index > 0 {
				version = version[:index] // platform suffix, such as 1.16.0-x86_64-linux
			}
			c.add(RubyGems, match[1], version, path)
		}
	}
	return scanner.Err()
}

// composer.lock: "packages" and "packages-dev" with name and version.
func parseComposerLock(c *collector, path string, contents []byte) error {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(contents, &lock); err != nil {
		return fmt.Errorf("not a valid composer.lock: %w", err)
	}
	for _, entry := range append(lock.Packages, lock.PackagesDev...) {
		if strings.HasPrefix(entry.Version, "dev-") {
			continue
		}
		c.add(Packagist, entry.Name, strings.TrimPrefix(entry.Version, "v"), path)
	}
	return nil
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
