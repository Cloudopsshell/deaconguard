package inventory

import (
	"fmt"
	"strings"
)

type Package struct {
	Name    string
	Version string
	Source  string
	Arch    string
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
		if len(fields) != 6 || fields[0] == "" || fields[2] == "" || fields[3] == "" || fields[5] == "" {
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
		packages = append(packages, Package{Name: fields[0], Version: evr, Source: source, Arch: fields[5]})
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("package inventory contains no installed RPM packages")
	}
	return packages, nil
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
