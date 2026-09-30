package scan

import (
	"fmt"
	"strings"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/target"
)

// Event is one line of live scan progress. Events describe what DeaconGuard is
// doing; they never contain command output or credentials.
type Event struct {
	Seq  int       `json:"seq"`
	Time time.Time `json:"time"`
	// Kind is phase, command, result, info, success, warning, error, finding,
	// prompt, or done.
	Kind    string `json:"kind"`
	Phase   string `json:"phase,omitempty"`
	Message string `json:"message"`
	Sudo    bool   `json:"sudo,omitempty"`
	// Status closes a phase: completed, partial, skipped, or failed.
	Status   string `json:"status,omitempty"`
	Severity string `json:"severity,omitempty"`
}

const (
	PhaseConnect = "connect"
	// maxLiveFindings bounds how many findings of one check are streamed.
	maxLiveFindings = 8
)

type reporter struct {
	emit  func(Event)
	phase string
}

func (r *reporter) send(event Event) {
	if r.emit == nil {
		return
	}
	if event.Phase == "" {
		event.Phase = r.phase
	}
	r.emit(event)
}

func (r *reporter) startPhase(phase, message string) {
	r.phase = phase
	r.send(Event{Kind: "phase", Message: message})
}

func (r *reporter) endPhase(status, message string) {
	kind := "success"
	switch status {
	case checks.StatusPartial, checks.StatusSkipped:
		kind = "warning"
	case checks.StatusFailed:
		kind = "error"
	}
	r.send(Event{Kind: kind, Status: status, Message: message})
}

func (r *reporter) info(format string, arguments ...any) {
	r.send(Event{Kind: "info", Message: fmt.Sprintf(format, arguments...)})
}

func (r *reporter) warn(format string, arguments ...any) {
	r.send(Event{Kind: "warning", Message: fmt.Sprintf(format, arguments...)})
}

// CommandStarted and CommandFinished implement target.CommandObserver.
func (r *reporter) CommandStarted(command string) {
	display, sudo := displayCommand(command)
	r.send(Event{Kind: "command", Message: display, Sudo: sudo})
}

func (r *reporter) CommandFinished(_ string, outputBytes int, elapsed time.Duration, err error) {
	message := fmt.Sprintf("%s in %s", formatBytes(outputBytes), formatDuration(elapsed))
	kind := "result"
	if err != nil {
		if status, ok := target.ExitStatus(err); ok {
			// Verification tools exit non-zero to report differences.
			message = fmt.Sprintf("exit %d · %s", status, message)
		} else {
			kind = "error"
			message = truncate(err.Error(), 200)
		}
	}
	r.send(Event{Kind: kind, Message: message})
}

func (r *reporter) findings(result checks.Result) {
	for index, finding := range result.Findings {
		if index == maxLiveFindings {
			r.info("… and %d more", len(result.Findings)-maxLiveFindings)
			break
		}
		message := finding.Title
		if finding.Evidence != "" {
			message += " — " + truncate(finding.Evidence, 120)
		}
		r.send(Event{Kind: "finding", Severity: strings.ToUpper(finding.Severity), Message: message})
	}
}

// displayCommand shows the command a check asked for, unwrapping DeaconGuard's
// own sudo wrapper so the live log reads naturally.
func displayCommand(command string) (string, bool) {
	for _, prefix := range []string{"sudo -n -- sh -c ", "sudo -S -p '' -- sh -c "} {
		if quoted, found := strings.CutPrefix(command, prefix); found {
			inner := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(quoted, "'"), "'"), `'\''`, "'")
			return truncate(strings.Join(strings.Fields(inner), " "), 160), true
		}
	}
	if command == "sudo -k -S -p '' -- true" {
		return "sudo -v   # verifying the sudo password", true
	}
	return truncate(strings.Join(strings.Fields(command), " "), 160), strings.HasPrefix(command, "sudo ")
}

func formatBytes(size int) string {
	switch {
	case size >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(size)/(1<<10))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

func formatDuration(elapsed time.Duration) string {
	if elapsed < time.Second {
		return fmt.Sprintf("%d ms", elapsed.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", elapsed.Seconds())
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}
