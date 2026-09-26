package platform

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

type Family string

const (
	Ubuntu       Family = "ubuntu"
	Debian       Family = "debian"
	AmazonLinux  Family = "amazon-linux"
	RHEL         Family = "rhel"
	CentOSStream Family = "centos-stream"
)

type Platform struct {
	Family    Family
	ID        string
	VersionID string
	Codename  string
	Major     int
}

func ParseOSRelease(contents string) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid os-release line %q", line)
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if values["ID"] == "" || values["VERSION_ID"] == "" {
		return nil, fmt.Errorf("os-release is missing ID or VERSION_ID")
	}
	return values, nil
}

func Detect(contents string) (Platform, error) {
	values, err := ParseOSRelease(contents)
	if err != nil {
		return Platform{}, err
	}
	id := strings.ToLower(values["ID"])
	version := values["VERSION_ID"]
	major, err := versionMajor(version)
	if err != nil {
		return Platform{}, fmt.Errorf("unsupported %s version %q", id, version)
	}

	platform := Platform{ID: id, VersionID: version, Codename: values["VERSION_CODENAME"], Major: major}
	switch id {
	case "ubuntu":
		supported := map[string]bool{"18.04": true, "20.04": true, "22.04": true, "24.04": true, "26.04": true}
		if !supported[version] {
			return Platform{}, fmt.Errorf("unsupported Ubuntu release %q", version)
		}
		platform.Family = Ubuntu
		if platform.Codename == "" {
			platform.Codename = map[string]string{
				"18.04": "bionic", "20.04": "focal", "22.04": "jammy",
				"24.04": "noble", "26.04": "resolute",
			}[version]
		}
	case "debian":
		if major != 12 && major != 13 {
			return Platform{}, fmt.Errorf("unsupported Debian release %q", version)
		}
		platform.Family = Debian
		codename := map[int]string{12: "bookworm", 13: "trixie"}[major]
		if platform.Codename != "" && platform.Codename != codename {
			return Platform{}, fmt.Errorf("Debian version %q does not match codename %q", version, platform.Codename)
		}
		platform.Codename = codename
	case "amzn":
		if version != "2023" {
			return Platform{}, fmt.Errorf("unsupported Amazon Linux release %q", version)
		}
		platform.Family = AmazonLinux
	case "rhel":
		if major < 8 || major > 9 {
			return Platform{}, fmt.Errorf("unsupported RHEL release %q", version)
		}
		platform.Family = RHEL
	case "centos":
		if strings.Contains(strings.ToLower(values["NAME"]), "centos stream") && (major == 9 || major == 10) {
			return Platform{}, fmt.Errorf("CentOS Stream %d is recognized but unsupported: no authoritative advisory feed is available", major)
		}
		return Platform{}, fmt.Errorf("unsupported CentOS release %q", version)
	default:
		return Platform{}, fmt.Errorf("unsupported Linux distribution %q", id)
	}

	return platform, nil
}

func versionMajor(version string) (int, error) {
	majorText, _, _ := strings.Cut(version, ".")
	return strconv.Atoi(majorText)
}
