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
	// Compiled Go programs are read here directly: their build information
	// is a small block inside files too large to send whole.
	var goNotes []string
	goNote := ""
	if executor.OnThisMachine() {
		var records []byte
		records, goNotes = collectGoBinaries()
		output = append(output, records...)
		goNote = goBinaryNote(records)
	}
	found := libraries.Parse(output)
	result := Result{Privileged: privileged, Libraries: &found, Notes: append(append([]string(nil), found.Notes...), goNotes...)}
	if goNote != "" {
		result.note("%s", goNote)
	}
	if !privileged {
		result.note("Ran without root, so projects in other users' folders may be missing.")
	}
	result.Summary = fmt.Sprintf("Found %d libraries in %d files", len(found.Libraries), found.Files)
	return result.finish(!privileged)
}
