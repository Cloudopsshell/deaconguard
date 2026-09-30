// Package buildinfo identifies the running DeaconGuard build. Release builds set
// the variables with -ldflags "-X deaconguard/internal/buildinfo.Version=...".
package buildinfo

import (
	"fmt"
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

// UserAgent identifies DeaconGuard to advisory feed servers.
func UserAgent() string {
	return "DeaconGuard/" + Version + " (+https://github.com/Cloudopsshell/deaconguard)"
}
