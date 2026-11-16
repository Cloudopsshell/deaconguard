// Package updates learns which DeaconGuard release is the newest, so the
// dashboard can say when the server is behind. It reads one short public
// file and sends nothing about the server that asks: no version, no
// identifier, no count of hosts.
package updates

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"deaconguard/internal/agentversion"
	"deaconguard/internal/buildinfo"
)

// StableURL holds the newest release's version, as plain text, such as
// "1.34.0". The install script reads the same file.
const StableURL = buildinfo.InstallURL + "/stable.txt"

const (
	// Interval is how often the newest release is asked for.
	Interval = 24 * time.Hour
	// timeout bounds one request, and maxBody what is read of the answer.
	timeout = 15 * time.Second
	maxBody = 64
)

// stable matches a final release's version: no pre-releases, no local builds.
var stable = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

var client = &http.Client{
	Timeout: timeout,
	// The file is served directly; a redirect elsewhere isn't followed.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Latest asks url for the newest release's version.
func Latest(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// The same for every server: the request doesn't say which version asks.
	request.Header.Set("User-Agent", "DeaconGuard")
	request.Header.Set("Accept", "text/plain")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s", url, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return "", err
	}
	version := strings.TrimPrefix(strings.TrimSpace(string(body)), "v")
	if len(body) > maxBody || !stable.MatchString(version) {
		return "", errors.New("the answer isn't a release version")
	}
	return version, nil
}

// Comparable reports whether current is a release that can be behind
// another: not a local build such as "dev" or "1.34.0-dev".
func Comparable(current string) bool {
	return buildinfo.IsRelease(current)
}

// Newer reports whether latest, a final release, is newer than current. A
// release candidate is behind its own final release, and ahead of the one
// before.
func Newer(current, latest string) bool {
	if !stable.MatchString(latest) || !Comparable(current) {
		return false
	}
	order, ok := agentversion.Compare(current, latest)
	return ok && order < 0
}
