package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"opsarmor/internal/remote"
	"opsarmor/internal/scanner"
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
	case "help", "--help", "-h":
		usage(output)
		return 0
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err != nil {
		fmt.Fprintf(diagnostics, "opsarmor: %v\n", err)
		return 1
	}
	return 0
}

func runHost(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("host requires add, list, or remove")
	}
	switch arguments[0] {
	case "add":
		address, username, port, keyPath, err := parseHostAdd(arguments[1:])
		if err != nil {
			return err
		}
		host, err := store.AddHost(address, username, port, keyPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Added %s (%s)\n", host.Address, host.ID)
	case "list":
		hosts, err := store.ListHosts()
		if err != nil {
			return err
		}
		if len(hosts) == 0 {
			fmt.Fprintln(output, "No hosts registered. Run: opsarmor host add ADDRESS --username USER")
			return nil
		}
		for _, host := range hosts {
			fmt.Fprintf(output, "%s  %s@%s:%d\n", host.ID, host.Username, host.Address, host.Port)
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

func parseHostAdd(arguments []string) (string, string, int, *string, error) {
	address, username, keyPath := "", "", ""
	port := 22
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--username" || argument == "--port" || argument == "--key-path" {
			if index+1 >= len(arguments) {
				return "", "", 0, nil, fmt.Errorf("%s requires a value", argument)
			}
			index++
			switch argument {
			case "--username":
				username = arguments[index]
			case "--key-path":
				keyPath = arguments[index]
			case "--port":
				if _, err := fmt.Sscan(arguments[index], &port); err != nil {
					return "", "", 0, nil, fmt.Errorf("invalid SSH port %q", arguments[index])
				}
			}
			continue
		}
		if strings.HasPrefix(argument, "-") {
			return "", "", 0, nil, fmt.Errorf("unknown host add option %q", argument)
		}
		if address != "" {
			return "", "", 0, nil, fmt.Errorf("host add accepts one address")
		}
		address = argument
	}
	if address == "" || username == "" {
		return "", "", 0, nil, fmt.Errorf("usage: opsarmor host add ADDRESS --username USER [--port PORT] [--key-path PATH]")
	}
	var keyPointer *string
	if keyPath != "" {
		keyPointer = &keyPath
	}
	return address, username, port, keyPointer, nil
}

func runScan(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	hostID, asJSON, err := parseIDAndJSON(arguments, "scan")
	if err != nil {
		return err
	}
	host, err := store.GetHost(hostID)
	if err != nil {
		return err
	}
	inventory, err := remote.CollectWithTrust(host, func(unknownKey *remote.UnknownHostKey) (bool, error) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return false, fmt.Errorf("%s; compare this fingerprint with AWS or another trusted source, then rerun in a terminal", unknownKey)
		}
		fmt.Fprintf(diagnostics,
			"\nFirst connection to %s presents an untrusted SSH host key.\nFingerprint: %s\nCompare this with AWS or another trusted source before accepting it.\n",
			host.Address, unknownKey.Fingerprint)
		fmt.Fprint(diagnostics, "Type 'trust' to save this key and retry the scan: ")
		answer, readErr := bufio.NewReader(input).ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return false, fmt.Errorf("read host-key confirmation: %w", readErr)
		}
		return strings.TrimSpace(answer) == "trust", nil
	})
	if err != nil {
		return err
	}
	report, err := scanner.Scan(inventory.OSRelease, inventory.DPKGStatus, inventory.RPMQuery, inventory.Kernel, nil, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return err
	}
	payload["host_id"] = host.ID
	payload["address"] = host.Address
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
	fmt.Fprintf(output, "Report: %v\nHost: %v (%v)\n", report["report_id"], report["address"], report["os"])
	fmt.Fprintf(output, "Scanned: %v\nFindings: %v\n", report["scanned_at"], report["finding_count"])
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

func usage(output io.Writer) {
	fmt.Fprintln(output, `OpsArmor scans registered Linux hosts over SSH using Go.

Commands:
  opsarmor host add ADDRESS --username USER [--port PORT] [--key-path PATH]
  opsarmor host list
  opsarmor host remove HOST_ID
  opsarmor scan HOST_ID [--json]
  opsarmor report REPORT_ID [--json]`)
}
