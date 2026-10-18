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
	Rocky        Family = "rocky"
	Alma         Family = "almalinux"
	Oracle       Family = "oracle"
	Fedora       Family = "fedora"
	OpenSUSELeap Family = "opensuse-leap"
	SLES         Family = "sles"
	Alpine       Family = "alpine"
)

type Platform struct {
	Family    Family
	ID        string
	VersionID string
	Codename  string
	Major     int
	// Minor is the minor version where it picks the feed, such as SLES
	// 15 SP6's 6.
	Minor int
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
	case "rocky", "almalinux", "ol":
		if major < 8 || major > 10 {
			return Platform{}, fmt.Errorf("unsupported %s release %q", values["NAME"], version)
		}
		platform.Family = map[string]Family{"rocky": Rocky, "almalinux": Alma, "ol": Oracle}[id]
	case "fedora":
		// Fedora releases are supported for about 13 months; Fedora's own
		// release data says which still get updates.
		if major < 40 {
			return Platform{}, fmt.Errorf("unsupported Fedora release %q", version)
		}
		platform.Family = Fedora
	case "opensuse-leap":
		if version != "15.6" && version != "16.0" {
			return Platform{}, fmt.Errorf("unsupported openSUSE Leap release %q: 15.6 and 16.0 are supported", version)
		}
		platform.Family = OpenSUSELeap
		platform.Minor = minorVersion(version)
	case "sles", "sled":
		minor := minorVersion(version)
		if !(major == 15 && minor >= 6) && major != 16 {
			return Platform{}, fmt.Errorf("unsupported SUSE Linux Enterprise release %q: 15 SP6 and later are supported", version)
		}
		platform.Family = SLES
		platform.Minor = minor
	case "alpine":
		// Alpine's security database exists per branch from 3.18; each
		// branch's end of life is in internal/lifecycle.
		// VERSION_ID is the full release, such as 3.22.1.
		minor := 0
		if fields := strings.Split(version, "."); len(fields) >= 2 {
			minor, _ = strconv.Atoi(fields[1])
		}
		if major != 3 || minor < 18 {
			return Platform{}, fmt.Errorf("unsupported Alpine Linux release %q: 3.18 and later are supported", version)
		}
		platform.Family = Alpine
		platform.Minor = minor
		platform.Codename = fmt.Sprintf("v%d.%d", major, minor)
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

func minorVersion(version string) int {
	_, minorText, _ := strings.Cut(version, ".")
	minor, _ := strconv.Atoi(minorText)
	return minor
}

func versionMajor(version string) (int, error) {
	majorText, _, _ := strings.Cut(version, ".")
	return strconv.Atoi(majorText)
}
