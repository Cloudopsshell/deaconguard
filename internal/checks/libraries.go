package checks

import (
	"fmt"
	"time"

	"deaconguard/internal/libraries"
)

// Libraries is the application library check. On the host it only lists the
// libraries; the server checks them against OSV (internal/osv), so an agent
// never decides what is vulnerable.
const Libraries = "libraries"

const librariesTimeout = 15 * time.Minute

func runLibraries(executor *Executor) Result {
	output, _, privileged, err := executor.RunPrivileged(libraries.CollectCommand, libraries.MaxOutputBytes, librariesTimeout)
	if err != nil && len(output) == 0 {
		return failed(fmt.Errorf("list the application libraries: %w", err))
	}
	found := libraries.Parse(output)
	result := Result{Privileged: privileged, Libraries: &found, Notes: append([]string(nil), found.Notes...)}
	if !privileged {
		result.note("Ran without root, so projects in other users' folders may be missing.")
	}
	result.Summary = fmt.Sprintf("Found %d libraries in %d files", len(found.Libraries), found.Files)
	return result.finish(!privileged)
}
