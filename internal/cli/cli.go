package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"opsarmor/internal/buildinfo"
	"opsarmor/internal/checks"
	"opsarmor/internal/remote"
	"opsarmor/internal/scan"
	"opsarmor/internal/server"
	"opsarmor/internal/store"
	"opsarmor/web"
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
		allowSudo := false
		addArguments := make([]string, 0, len(arguments))
		for _, argument := range arguments[1:] {
			if argument == "--allow-sudo" {
				allowSudo = true
				continue
			}
			addArguments = append(addArguments, argument)
		}
		address, username, port, keyPath, err := parseHostAdd(addArguments)
		if err != nil {
			return err
		}
		host, err := store.AddHost(address, username, port, keyPath)
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
			fmt.Fprintln(output, "No hosts registered. Run: opsarmor host add ADDRESS --username USER")
			return nil
		}
		for _, host := range hosts {
			sudo := ""
			if host.AllowSudo {
				sudo = "  (sudo allowed)"
			}
			fmt.Fprintf(output, "%s  %s@%s:%d%s\n", host.ID, host.Username, host.Address, host.Port, sudo)
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
	selected := []string{checks.Packages}
	remaining := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
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
	hostID, asJSON, err := parseIDAndJSON(remaining, "scan")
	if err != nil {
		return err
	}
	host, err := store.GetHost(hostID)
	if err != nil {
		return err
	}
	confirm := func(unknownKey *remote.UnknownHostKey) (bool, error) {
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
	}
	report, err := scan.Run(host, selected, scan.Options{
		Remote:       remote.TerminalOptions(host, confirm),
		SudoPassword: remote.TerminalSecret(fmt.Sprintf("[sudo] password for %s on %s: ", host.Username, host.Address)),
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

const defaultListen = "127.0.0.1:7480"

func runServe(arguments []string, output io.Writer) error {
	listen := defaultListen
	for index := 0; index < len(arguments); index++ {
		if arguments[index] != "--listen" || index+1 >= len(arguments) {
			return fmt.Errorf("usage: opsarmor serve [--listen 127.0.0.1:PORT]")
		}
		index++
		listen = arguments[index]
	}
	if !server.IsLoopback(listen) {
		return fmt.Errorf("the web UI only listens on a loopback address such as %s", defaultListen)
	}
	handler, err := server.New(web.Files(), nil)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Restore default signal handling so a second Ctrl+C exits at once.
		stop()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	fmt.Fprintf(output, "OpsArmor %s web UI: http://%s\nData: %s\nPress Ctrl+C to stop.\n", buildinfo.Version, listener.Addr(), store.DatabasePath())
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	fmt.Fprintln(output, "Waiting for running scans to finish (press Ctrl+C again to quit now)...")
	handler.Close()
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
	fmt.Fprintln(output, `OpsArmor scans registered Linux hosts over SSH using Go.

Commands:
  opsarmor host add ADDRESS --username USER [--port PORT] [--key-path PATH] [--allow-sudo]
  opsarmor host list
  opsarmor host sudo HOST_ID on|off
  opsarmor host remove HOST_ID
  opsarmor scan HOST_ID [--checks packages,integrity,malware,config,antivirus] [--json]
  opsarmor report REPORT_ID [--json]
  opsarmor serve [--listen 127.0.0.1:PORT]   web UI, default http://127.0.0.1:7480
  opsarmor version`)
}
