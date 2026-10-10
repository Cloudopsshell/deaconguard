// Package buildinfo identifies the running DeaconGuard build. Release builds set
// the variables with -ldflags "-X deaconguard/internal/buildinfo.Version=...".
package buildinfo

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	// Version is the semantic version of a release, such as "0.1.0".
	Version = "dev"
	// Commit is the Git commit the binary was built from.
	Commit = ""
	// Date is when the binary was built, in RFC 3339.
	Date = ""
)

func init() {
	// A plain `go build` of a Git checkout still records the commit.
	if Commit != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			Commit = setting.Value
		case "vcs.time":
			if Date == "" {
				Date = setting.Value
			}
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if modified && Commit != "" {
		Commit += "-dirty"
	}
}

// Info is the build description returned by the API.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Go      string `json:"go"`
}

func Get() Info {
	return Info{Version: Version, Commit: Commit, Date: Date, Go: runtime.Version()}
}

// String is the one-line description printed by `deaconguard version`.
func String() string {
	commit, dirty := strings.CutSuffix(Commit, "-dirty")
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if dirty {
		commit += "-dirty"
	}
	if commit == "" {
		commit = "unknown"
	}
	date := Date
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("deaconguard %s (commit %s, built %s, %s %s/%s)", Version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// Repository is where DeaconGuard's source and releases are published.
const Repository = "https://github.com/Cloudopsshell/deaconguard"

// UserAgent identifies DeaconGuard to advisory feed servers.
func UserAgent() string {
	return "DeaconGuard/" + Version + " (+" + Repository + ")"
}

// releaseVersion matches the versions of published releases, such as 0.2.0 or
// 0.2.0-rc.1, and not local builds such as 0.1.1-3-gabc1234-dirty or dev.
var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)(\.[0-9]+)?)?$`)

// InstallURL serves the install script: install.sh from the repository's
// main branch, as plain text.
const InstallURL = "https://get.deaconguard.io"

// AgentInstallCommand is the command line that installs the DeaconGuard agent
// and enrolls it with token, a one-time enrollment token; an empty token makes
// the installer ask for it. A release build pins its own version, so agents
// match their server; other builds install the latest release. The installer
// needs root; `sudo -E` passes the variables to it through the environment,
// so the token is not on a command line other users can see.
func AgentInstallCommand(token string) string {
	environment := ""
	if releaseVersion.MatchString(Version) {
		environment = "DEACONGUARD_VERSION=" + Version + " "
	}
	if token == "" {
		return "curl -fsSL " + InstallURL + " | " + environment + "sudo -E sh -s -- --agent"
	}
	// Tokens are base64url and dots, so they need no shell quoting.
	return "curl -fsSL " + InstallURL + " | " + environment + "DEACONGUARD_TOKEN=" + token + " sudo -E sh -"
}
