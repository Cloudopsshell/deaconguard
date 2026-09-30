package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"opsarmor/internal/agent"
	"opsarmor/internal/buildinfo"
	"opsarmor/internal/checks"
	"opsarmor/internal/local"
	"opsarmor/internal/scan"
	"opsarmor/internal/store"
)

func Run(arguments []string, input io.Reader, output, diagnostics io.Writer) int {
	if input == nil {
		input = os.Stdin
	}
	if output == nil {
		output = os.Stdout
	}
	if diagnostics == nil {
		diagnostics = os.Stderr
	}
	if len(arguments) == 0 {
		usage(diagnostics)
		return 2
	}
	var err error
	switch arguments[0] {
	case "host":
		err = runHost(arguments[1:], output)
	case "scan":
		err = runScan(arguments[1:], input, output, diagnostics)
	case "report":
		err = runReport(arguments[1:], output)
	case "serve":
		err = runServe(arguments[1:], output)
	case "user":
		err = runUser(arguments[1:], input, output, diagnostics)
	case "agent":
		err = runAgent(arguments[1:], output, diagnostics)
	case "token":
		err = runToken(arguments[1:], output)
	case "version", "--version", "-v":
		fmt.Fprintln(output, buildinfo.String())
		return 0
	case "help", "--help", "-h":
		usage(output)
		return 0
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err != nil {
		fmt.Fprintf(diagnostics, "opsarmor: %v\n", err)
		if errors.Is(err, agent.ErrRemoved) {
			// The agent service does not restart on this status.
			return 3
		}
		return 1
	}
	return 0
}

func runHost(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("host requires add, list, sudo, or remove")
	}
	switch arguments[0] {
	case "add":
		// Registers this machine; --local is accepted for scripts written for 0.2 previews.
		allowSudo := false
		for _, argument := range arguments[1:] {
			switch argument {
			case "--allow-sudo":
				allowSudo = true
			case "--local":
			default:
				return fmt.Errorf("opsarmor host add registers this machine and takes no address: %w", scan.ErrSSHRemoved)
			}
		}
		if _, err := local.New(); err != nil {
			return err
		}
		host, err := store.AddLocalHost(local.Hostname(), local.Username())
		if err != nil {
			return err
		}
		if allowSudo {
			if host, err = store.SetAllowSudo(host.ID, true); err != nil {
				return err
			}
		}
		fmt.Fprintf(output, "Added %s (%s)\n", host.Address, host.ID)
	case "sudo":
		if len(arguments) != 3 || (arguments[2] != "on" && arguments[2] != "off") {
			return fmt.Errorf("usage: opsarmor host sudo HOST_ID on|off")
		}
		host, err := store.SetAllowSudo(arguments[1], arguments[2] == "on")
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Sudo for deeper checks on %s: %s\n", host.Address, arguments[2])
	case "list":
		hosts, err := store.ListHosts()
		if err != nil {
			return err
		}
		if len(hosts) == 0 {
			fmt.Fprintln(output, "No hosts registered. Run opsarmor host add to add this machine, or enroll agents: opsarmor token create")
			return nil
		}
		for _, host := range hosts {
			sudo := ""
			if host.AllowSudo {
				sudo = "  (sudo allowed)"
			}
			if !host.Scannable() {
				fmt.Fprintf(output, "%s  %s  (SSH host; scanning removed in 0.2.0, earlier results kept)\n", host.ID, host.Address)
				continue
			}
			if host.Transport == store.TransportAgent {
				fmt.Fprintf(output, "%s  %s  (agent)\n", host.ID, host.Address)
				continue
			}
			fmt.Fprintf(output, "%s  this machine (%s, as %s)%s\n", host.ID, host.Address, host.Username, sudo)
		}
	case "remove":
		if len(arguments) != 2 {
			return fmt.Errorf("usage: opsarmor host remove HOST_ID")
		}
		host, err := store.RemoveHost(arguments[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Removed %s (%s)\n", host.Address, host.ID)
	default:
		return fmt.Errorf("unknown host action %q", arguments[0])
	}
	return nil
}

func runScan(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	selected := []string{checks.Packages}
	remaining := make([]string, 0, len(arguments))
	scanLocal, allowSudo := false, false
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--local":
			scanLocal = true
			continue
		case "--allow-sudo":
			allowSudo = true
			continue
		}
		if arguments[index] != "--checks" {
			remaining = append(remaining, arguments[index])
			continue
		}
		if index+1 >= len(arguments) {
			return fmt.Errorf("--checks requires a comma-separated list such as packages,integrity,malware,config,antivirus")
		}
		index++
		selected = strings.Split(arguments[index], ",")
	}
	selected, err := checks.Normalize(selected)
	if err != nil {
		return err
	}
	var host store.Host
	var asJSON bool
	if scanLocal {
		// A one-off scan of this machine; it is saved but not tied to a registered host.
		for _, argument := range remaining {
			if argument != "--json" {
				return fmt.Errorf("usage: opsarmor scan --local [--allow-sudo] [--checks LIST] [--json]")
			}
			asJSON = true
		}
		host = store.Host{Address: local.Hostname(), Username: local.Username(), Transport: store.TransportLocal, AllowSudo: allowSudo}
	} else {
		if allowSudo {
			return fmt.Errorf("--allow-sudo applies to --local scans; for a registered host use: opsarmor host sudo HOST_ID on")
		}
		var hostID string
		if hostID, asJSON, err = parseIDAndJSON(remaining, "scan"); err != nil {
			return err
		}
		if host, err = store.GetHost(hostID); err != nil {
			return err
		}
		if host.Transport == store.TransportAgent {
			return scanThroughAgent(host, selected, asJSON, output, diagnostics)
		}
	}
	report, err := scan.Run(host, selected, scan.Options{
		SudoPassword: terminalSecret(fmt.Sprintf("[sudo] password for %s on %s: ", host.Username, host.Address), diagnostics),
	})
	if err != nil {
		return err
	}
	// Round-trip through JSON so the saved and printed report match what
	// `opsarmor report` later reads back.
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return err
	}
	saved, err := store.SaveReport(payload)
	if err != nil {
		return err
	}
	return showReport(saved, asJSON, output)
}

func runReport(arguments []string, output io.Writer) error {
	reportID, asJSON, err := parseIDAndJSON(arguments, "report")
	if err != nil {
		return err
	}
	report, err := store.GetReport(reportID)
	if err != nil {
		return err
	}
	return showReport(report, asJSON, output)
}

func parseIDAndJSON(arguments []string, command string) (string, bool, error) {
	id := ""
	asJSON := false
	for _, argument := range arguments {
		if argument == "--json" {
			asJSON = true
			continue
		}
		if strings.HasPrefix(argument, "-") {
			return "", false, fmt.Errorf("unknown %s option %q", command, argument)
		}
		if id != "" {
			return "", false, fmt.Errorf("usage: opsarmor %s ID [--json]", command)
		}
		id = argument
	}
	if id == "" {
		return "", false, fmt.Errorf("usage: opsarmor %s ID [--json]", command)
	}
	return id, asJSON, nil
}

func showReport(report map[string]any, asJSON bool, output io.Writer) error {
	if asJSON {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintf(output, "Report: %v\nHost: %v (%v)\nScanned: %v\n", report["report_id"], report["address"], report["os"], report["scanned_at"])
	showCheckResults(report, output)
	if _, packages := report["finding_count"]; !packages {
		return nil
	}
	fmt.Fprintf(output, "\nPackage vulnerabilities: %v findings\n", report["finding_count"])
	fmt.Fprintf(output, "Coverage: %v\nMaintenance: %v\n", report["coverage"], report["maintenance"])
	if database, ok := report["advisory_database"].(map[string]any); ok {
		freshness := "current"
		if stale, _ := database["feed_stale"].(bool); stale {
			freshness = "STALE"
		}
		fmt.Fprintf(output, "Advisory data: %s, age %v hours\n", freshness, database["feed_age_hours"])
	}
	if unsupported, ok := report["unsupported_cves"].([]any); ok && len(unsupported) > 0 {
		fmt.Fprintf(output, "Rules not fully evaluated: %d\n", len(unsupported))
		for _, value := range unsupported {
			item, ok := value.(map[string]any)
			if ok {
				fmt.Fprintf(output, "  NOT EVALUATED %v: %v\n", item["id"], item["reason"])
			}
		}
	}
	if findings, ok := report["findings"].([]any); ok {
		for _, value := range findings {
			item, ok := value.(map[string]any)
			if !ok {
				continue
			}
			fixed := item["fixed_version"]
			if fixed == nil || fixed == "" {
				fixed = "no fixed version listed"
			}
			fmt.Fprintf(output, "%-8v %-18v %v %v -> %v\n", item["severity"], item["id"], item["package"], item["installed_version"], fixed)
		}
	}
	return nil
}

func showCheckResults(report map[string]any, output io.Writer) {
	results, ok := report["check_results"].(map[string]any)
	if !ok {
		return
	}
	for _, definition := range checks.Definitions() {
		result, ok := results[definition.ID].(map[string]any)
		if !ok {
			continue
		}
		access := "without sudo"
		if privileged, _ := result["privileged"].(bool); privileged {
			access = "with sudo"
		}
		fmt.Fprintf(output, "\n%s: %v (%s) - %v\n", definition.Name, result["status"], access, result["summary"])
		if message, _ := result["error"].(string); message != "" {
			fmt.Fprintf(output, "  ERROR %s\n", message)
		}
		if findings, ok := result["findings"].([]any); ok {
			for _, value := range findings {
				if finding, ok := value.(map[string]any); ok {
					fmt.Fprintf(output, "  %-8v %v: %v\n", finding["severity"], finding["title"], finding["evidence"])
				}
			}
		}
		if notes, ok := result["notes"].([]any); ok {
			for _, note := range notes {
				fmt.Fprintf(output, "  note: %v\n", note)
			}
		}
	}
}

func usage(output io.Writer) {
	fmt.Fprintln(output, `OpsArmor scans Linux machines against official security advisories. It
scans the machine it runs on, and machines running the OpsArmor agent that
have enrolled with an OpsArmor server.

Scanning:
  opsarmor host add [--allow-sudo]    register this machine (Linux)
  opsarmor host list
  opsarmor host sudo HOST_ID on|off
  opsarmor host remove HOST_ID        for an agent host, also revokes its agent
  opsarmor scan HOST_ID [--checks packages,integrity,malware,config,antivirus] [--json]
  opsarmor scan --local [--allow-sudo] [--checks LIST] [--json]   scan this machine without registering it
  opsarmor report REPORT_ID [--json]

Web UI and server:
  opsarmor serve                       local web UI at http://127.0.0.1:7480, no sign-in
  opsarmor serve --listen 0.0.0.0:8443 [--tls-cert FILE --tls-key FILE]
                                       server: HTTPS dashboard with sign-in, agents enroll
  opsarmor user add|passwd USERNAME [--password-stdin]
  opsarmor user list | remove USERNAME
  opsarmor token create --server-url https://HOST:8443   one-time agent token, valid 24 hours

Agent (on each machine to scan):
  opsarmor agent enroll TOKEN [--force]   enroll with the server that made TOKEN
  opsarmor agent run                      wait for scans (the opsarmor-agent service)
  opsarmor agent status

  opsarmor version`)
}

// terminalSecret asks for a secret on the terminal without echoing it.
func terminalSecret(prompt string, diagnostics io.Writer) func(retry error) ([]byte, error) {
	return func(retry error) ([]byte, error) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("a sudo password is required; run the scan in a terminal or allow passwordless sudo")
		}
		if retry != nil {
			fmt.Fprintf(diagnostics, "%s. ", retry)
		}
		fmt.Fprint(diagnostics, prompt)
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(diagnostics)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		return secret, nil
	}
}
