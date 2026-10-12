package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
	"deaconguard/internal/local"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
	"deaconguard/internal/yararules"
)

const auditUsage = "usage: deaconguard audit HOST_ID [--advanced] [--json]\n       deaconguard audit --local [--allow-sudo] [--advanced] [--json]"

// runAudit runs a handover audit, every check graded together, and prints
// its grade and what to fix.
func runAudit(arguments []string, output, diagnostics io.Writer) error {
	auditLocal, allowSudo, advanced, asJSON := false, false, false, false
	hostID := ""
	for _, argument := range arguments {
		switch argument {
		case "--local":
			auditLocal = true
		case "--allow-sudo":
			allowSudo = true
		case "--advanced":
			advanced = true
		case "--json":
			asJSON = true
		default:
			if strings.HasPrefix(argument, "-") || hostID != "" {
				return fmt.Errorf("%s", auditUsage)
			}
			hostID = argument
		}
	}
	if auditLocal == (hostID != "") || (allowSudo && !auditLocal) {
		return fmt.Errorf("%s", auditUsage)
	}
	selected := append([]string(nil), audit.Checks...)
	if advanced {
		selected = append(selected, checks.YARA)
	}
	selected, err := checks.Normalize(selected)
	if err != nil {
		return err
	}

	host := store.Host{Address: local.Hostname(), Username: local.Username(), Transport: store.TransportLocal, AllowSudo: allowSudo}
	var report map[string]any
	if !auditLocal {
		if host, err = store.GetHost(hostID); err != nil {
			return err
		}
	}
	if host.Transport == store.TransportAgent {
		id, err := queueForAgent(host, selected, true, diagnostics)
		if err != nil {
			return err
		}
		if report, err = waitForAgent(id); err != nil {
			return err
		}
	} else {
		ran, err := scan.Run(host, selected, scan.Options{
			SudoPassword: terminalSecret(fmt.Sprintf("[sudo] password for %s on %s: ", host.Username, host.Address), diagnostics),
			YARARules:    yararules.Provider(),
		})
		if err != nil {
			return err
		}
		// Through JSON, so what is saved and what is graded match.
		encoded, err := json.Marshal(ran)
		if err != nil {
			return err
		}
		var payload map[string]any
		if err := json.Unmarshal(encoded, &payload); err != nil {
			return err
		}
		if report, err = store.SaveReport(payload); err != nil {
			return err
		}
		id, _ := report["report_id"].(string)
		if err := store.MarkAudit(id); err != nil {
			return err
		}
		store.Audit(local.Username()+" (cli)", "audit.start", host.Address, strings.Join(selected, ", "), "")
	}

	id, _ := report["report_id"].(string)
	record, err := store.GetScan(id)
	if err != nil {
		return err
	}
	exceptions, err := store.Exceptions(record.HostID)
	if err != nil {
		return err
	}
	summary, err := audit.Grade(record, report, exceptions, time.Now())
	if err != nil {
		return err
	}
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{"audit_id": id, "host": record.Address, "summary": summary})
	}
	showAudit(id, record, summary, output)
	return nil
}

func showAudit(id string, record store.Scan, summary audit.Summary, output io.Writer) {
	fmt.Fprintf(output, "Audit %s of %s (%s)\n", id, record.Address, record.OS)
	fmt.Fprintf(output, "\nGrade %s · score %d/100 · %d passed, %d failed, %d accepted, %d not applicable\n",
		summary.Grade, summary.Score, summary.Counts.Passed, summary.Counts.Failed, summary.Counts.Accepted, summary.Counts.NotApplicable)
	for _, reason := range summary.Caps {
		fmt.Fprintf(output, "  ! %s\n", reason)
	}
	for _, reason := range summary.Incomplete {
		fmt.Fprintf(output, "  incomplete: %s\n", reason)
	}
	if summary.Packages != nil {
		fmt.Fprintf(output, "\nPackages: %d critical and %d high vulnerabilities have a fix available\n",
			summary.Packages.Actionable.Critical, summary.Packages.Actionable.High)
	}
	for _, check := range summary.Checks {
		fmt.Fprintf(output, "%s: %s · %s\n", check.Name, check.Status, check.Summary)
	}
	fmt.Fprintln(output, "\nFailed controls:")
	failedAny := false
	for _, control := range summary.Controls {
		if control.Status != checks.ControlFail {
			continue
		}
		failedAny = true
		fmt.Fprintf(output, "  %-7s %-8s %s\n          %s\n          Fix: %s\n", control.ID, strings.ToUpper(control.Severity), control.Title, control.Evidence, control.Remediation)
	}
	if !failedAny {
		fmt.Fprintln(output, "  none")
	}
	fmt.Fprintln(output, "\nThe full audit, with every control and the machine's inventory, is on the dashboard's Audits page.")
}
