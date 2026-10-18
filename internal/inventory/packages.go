package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

type Package struct {
	Name    string
	Version string
	Source  string
	Arch    string
	// SigningKey is the ID of the key an RPM package was signed with, in
	// lower-case hex; empty for DPKG, unsigned packages, and agents before
	// 0.19.0.
	SigningKey string
}

func ParseDPKGStatus(contents string) ([]Package, error) {
	packages := make([]Package, 0)
	for _, stanza := range strings.Split(strings.TrimSpace(contents), "\n\n") {
		fields := make(map[string]string)
		for _, line := range strings.Split(stanza, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			name, value, found := strings.Cut(line, ": ")
			if found {
				fields[name] = value
			}
		}
		if fields["Status"] != "install ok installed" || fields["Package"] == "" || fields["Version"] == "" {
			continue
		}
		source := fields["Source"]
		if source == "" {
			source = fields["Package"]
		} else if sourceName, _, found := strings.Cut(source, " "); found {
			source = sourceName
		}
		packages = append(packages, Package{
			Name:    fields["Package"],
			Version: fields["Version"],
			Source:  source,
			Arch:    fields["Architecture"],
		})
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("package inventory contains no installed dpkg packages")
	}
	return packages, nil
}

// ParseRPMQuery parses tab-separated output from rpm -qa with epoch, version,
// release, source RPM, and architecture fields.
func ParseRPMQuery(contents string) ([]Package, error) {
	packages := make([]Package, 0)
	for _, line := range strings.Split(strings.TrimSpace(contents), "\n") {
		fields := strings.Split(line, "\t")
		if (len(fields) != 6 && len(fields) != 7) || fields[0] == "" || fields[2] == "" || fields[3] == "" || fields[5] == "" {
			return nil, fmt.Errorf("invalid RPM inventory row %q", line)
		}
		evr := fields[2] + "-" + fields[3]
		if fields[1] != "" && fields[1] != "(none)" && fields[1] != "0" {
			evr = fields[1] + ":" + evr
		}
		source := sourcePackageName(fields[4])
		if source == "" {
			source = fields[0]
		}
		item := Package{Name: fields[0], Version: evr, Source: source, Arch: fields[5]}
		if len(fields) == 7 {
			item.SigningKey = signingKey(fields[6])
		}
		packages = append(packages, item)
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("package inventory contains no installed RPM packages")
	}
	return packages, nil
}

var keyID = regexp.MustCompile(`(?i)Key ID ([0-9a-f]{8,16})`)

// signingKey takes the key ID from rpm's pgpsig text, such as "RSA/SHA256,
// Tue 01 Oct 2024, Key ID 199e2f91fd431d51".
func signingKey(signature string) string {
	if match := keyID.FindStringSubmatch(signature); match != nil {
		return strings.ToLower(match[1])
	}
	return ""
}

func sourcePackageName(sourceRPM string) string {
	sourceRPM = strings.TrimSuffix(sourceRPM, ".src.rpm")
	if sourceRPM == "" || sourceRPM == "(none)" {
		return ""
	}
	last := strings.LastIndexByte(sourceRPM, '-')
	if last < 0 {
		return sourceRPM
	}
	previous := strings.LastIndexByte(sourceRPM[:last], '-')
	if previous < 0 {
		return sourceRPM[:last]
	}
	return sourceRPM[:previous]
}

// ParseAPKInstalled parses Alpine's /lib/apk/db/installed: one block per
// package, separated by blank lines, with lines such as P:name, V:version,
// A:architecture and o:origin (the source package, which Alpine's security
// database is keyed by).
func ParseAPKInstalled(contents string) ([]Package, error) {
	packages := make([]Package, 0)
	for _, block := range strings.Split(strings.TrimSpace(contents), "\n\n") {
		fields := make(map[string]string)
		for _, line := range strings.Split(block, "\n") {
			if len(line) > 2 && line[1] == ':' {
				if _, seen := fields[line[:1]]; !seen {
					fields[line[:1]] = line[2:]
				}
			}
		}
		if fields["P"] == "" || fields["V"] == "" {
			continue
		}
		source := fields["o"]
		if source == "" {
			source = fields["P"]
		}
		packages = append(packages, Package{Name: fields["P"], Version: fields["V"], Source: source, Arch: fields["A"]})
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("package inventory contains no installed apk packages")
	}
	return packages, nil
}
