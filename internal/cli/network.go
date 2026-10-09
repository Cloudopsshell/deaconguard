package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"deaconguard/internal/agent"
	"deaconguard/internal/agentapi"
	"deaconguard/internal/buildinfo"
	"deaconguard/internal/local"
	"deaconguard/internal/server"
	"deaconguard/internal/store"
	"deaconguard/internal/tlscert"
	"deaconguard/web"
)

const (
	defaultListen = "127.0.0.1:7480"
	// metaServerPin records the server certificate's pin for deaconguard token create.
	metaServerPin = "server_pin"
)

func runServe(arguments []string, output io.Writer) error {
	listen, certificatePath, keyPath := defaultListen, "", ""
	for index := 0; index < len(arguments); index++ {
		if index+1 >= len(arguments) {
			return fmt.Errorf("usage: deaconguard serve [--listen ADDRESS:PORT] [--tls-cert FILE --tls-key FILE]")
		}
		switch arguments[index] {
		case "--listen":
			listen = arguments[index+1]
		case "--tls-cert":
			certificatePath = arguments[index+1]
		case "--tls-key":
			keyPath = arguments[index+1]
		default:
			return fmt.Errorf("unknown serve option %q", arguments[index])
		}
		index++
	}
	if (certificatePath == "") != (keyPath == "") {
		return fmt.Errorf("--tls-cert and --tls-key go together")
	}
	if server.IsLoopback(listen) && certificatePath == "" {
		handler, err := server.New(web.Files(), nil)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "DeaconGuard %s web UI: http://%s\nData: %s\nPress Ctrl+C to stop.\n", buildinfo.Version, listener.Addr(), store.DatabasePath())
		return serveUntilStopped(handler, listener, output)
	}

	var certificate tls.Certificate
	var err error
	created := false
	if certificatePath != "" {
		certificate, err = tlscert.Load(certificatePath, keyPath)
	} else {
		certificate, created, err = tlscert.Ensure(filepath.Join(store.DataDir(), "tls"), local.Hostname())
	}
	if err != nil {
		return err
	}
	pin := agentapi.PublicKeyPin(certificate.Leaf)
	handler, err := server.NewNetwork(web.Files(), nil, pin)
	if err != nil {
		return err
	}
	if err := store.SetMeta(metaServerPin, pin); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	fmt.Fprintf(output, "DeaconGuard %s server: https://%s\n", buildinfo.Version, displayAddress(listener.Addr()))
	if created {
		fmt.Fprintf(output, "Created a self-signed certificate in %s. Browsers warn about it once;\n",
			filepath.Join(store.DataDir(), "tls"))
		fmt.Fprintln(output, "agents trust it through the fingerprint in their enrollment token.")
	}
	fmt.Fprintf(output, "Certificate public key (SHA-256): %s\nData: %s\nPress Ctrl+C to stop.\n", pin, store.DatabasePath())
	return serveUntilStopped(handler, listener, output)
}

func displayAddress(address net.Addr) string {
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = local.Hostname()
	}
	return net.JoinHostPort(host, port)
}

func serveUntilStopped(handler *server.Server, listener net.Listener, output io.Writer) error {
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
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
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	fmt.Fprintln(output, "Waiting for running scans to finish (press Ctrl+C again to quit now)...")
	handler.Close()
	return nil
}

func runUser(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("user requires add, passwd, list, or remove")
	}
	switch arguments[0] {
	case "list":
		users, err := store.ListUsers()
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Fprintln(output, noAccountsMessage+" Create one: deaconguard user add USERNAME")
		}
		for _, user := range users {
			fmt.Fprintf(output, "%s  (created %s)\n", user.Username, user.CreatedAt)
		}
		return nil
	case "remove":
		if len(arguments) != 2 {
			return fmt.Errorf("usage: deaconguard user remove USERNAME")
		}
		if err := store.RemoveUser(arguments[1]); err != nil {
			return err
		}
		store.Audit(local.Username()+" (cli)", "user.remove", arguments[1], "", "")
		fmt.Fprintf(output, "Removed %s and signed out their sessions\n", arguments[1])
		return nil
	case "add", "passwd":
	default:
		return fmt.Errorf("unknown user action %q", arguments[0])
	}
	username, fromStdin := "", false
	for _, argument := range arguments[1:] {
		switch {
		case argument == "--password-stdin":
			fromStdin = true
		case strings.HasPrefix(argument, "-") || username != "":
			return fmt.Errorf("usage: deaconguard user %s USERNAME [--password-stdin]", arguments[0])
		default:
			username = argument
		}
	}
	if username == "" {
		return fmt.Errorf("usage: deaconguard user %s USERNAME [--password-stdin]", arguments[0])
	}
	password, err := readNewPassword(input, diagnostics, fromStdin)
	if err != nil {
		return err
	}
	defer clear(password)
	if arguments[0] == "add" {
		if _, err := store.AddUser(username, password); err != nil {
			return err
		}
		store.Audit(local.Username()+" (cli)", "user.add", username, "", "")
		fmt.Fprintf(output, "Created %s. Sign in to the dashboard served by: deaconguard serve --listen 0.0.0.0:8443\n", username)
		return nil
	}
	if err := store.SetPassword(username, password); err != nil {
		return err
	}
	store.Audit(local.Username()+" (cli)", "user.passwd", username, "", "")
	fmt.Fprintf(output, "Changed the password of %s and signed out their sessions\n", username)
	return nil
}

func readNewPassword(input io.Reader, diagnostics io.Writer, fromStdin bool) ([]byte, error) {
	if fromStdin {
		line, err := bufio.NewReader(input).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		password := []byte(strings.TrimRight(line, "\r\n"))
		return password, store.ValidatePassword(password)
	}
	terminal, closeTerminal, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("run this in a terminal, or pass the password with --password-stdin")
	}
	defer closeTerminal()
	return promptNewPassword(terminal, diagnostics)
}

// promptNewPassword asks for a new password twice on terminal.
func promptNewPassword(terminal *os.File, diagnostics io.Writer) ([]byte, error) {
	fmt.Fprintf(diagnostics, "Password (at least %d characters): ", store.MinPasswordLength)
	password, err := term.ReadPassword(int(terminal.Fd()))
	fmt.Fprintln(diagnostics)
	if err != nil {
		return nil, err
	}
	if err := store.ValidatePassword(password); err != nil {
		return nil, err
	}
	fmt.Fprint(diagnostics, "Repeat the password: ")
	repeated, err := term.ReadPassword(int(terminal.Fd()))
	fmt.Fprintln(diagnostics)
	if err != nil {
		return nil, err
	}
	defer clear(repeated)
	if string(repeated) != string(password) {
		return nil, fmt.Errorf("the passwords do not match")
	}
	return password, nil
}

func runToken(arguments []string, output io.Writer) error {
	if len(arguments) != 3 || arguments[0] != "create" || arguments[1] != "--server-url" {
		return fmt.Errorf("usage: deaconguard token create --server-url https://HOST:8443")
	}
	serverURL := strings.TrimSuffix(strings.TrimSpace(arguments[2]), "/")
	if err := agentapi.ValidateServerURL(serverURL); err != nil {
		return err
	}
	pin, err := store.Meta(metaServerPin)
	if err != nil {
		return err
	}
	if pin == "" {
		return fmt.Errorf("start the server once first, so it has a certificate: deaconguard serve --listen 0.0.0.0:8443")
	}
	token, secret, err := store.CreateEnrollmentToken(serverURL, local.Username()+" (cli)")
	if err != nil {
		return err
	}
	store.Audit(local.Username()+" (cli)", "token.create", token.ID[:8], "for "+serverURL+", expires "+token.ExpiresAt, "")
	encoded := agentapi.Token{ServerURL: serverURL, Pin: pin, Secret: secret}.Encode()
	fmt.Fprintf(output, "One-time enrollment token, valid until %s:\n\n  %s\n\n", token.ExpiresAt, encoded)
	fmt.Fprintf(output, "On the machine to scan, run:\n\n  %s\n\n", buildinfo.AgentInstallCommand(encoded))
	fmt.Fprintln(output, "If DeaconGuard is already installed there, run: sudo deaconguard setup agent (it asks for the token)")
	return nil
}

func runAgent(arguments []string, output, diagnostics io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("agent requires enroll, run, or status")
	}
	path := agent.ConfigPath()
	switch arguments[0] {
	case "enroll":
		token, force := "", false
		for _, argument := range arguments[1:] {
			switch {
			case argument == "--force":
				force = true
			case token == "" && !strings.HasPrefix(argument, "-"):
				token = argument
			default:
				return fmt.Errorf("usage: deaconguard agent enroll TOKEN [--force]")
			}
		}
		if token == "" {
			return fmt.Errorf("usage: deaconguard agent enroll TOKEN [--force]")
		}
		config, err := agent.Enroll(context.Background(), token, path, force)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Enrolled %s with %s as host %s.\nSaved %s\n", local.Hostname(), config.ServerURL, config.HostID, path)
		if os.Geteuid() == 0 {
			fmt.Fprintln(output, "Start the agent: sudo systemctl enable --now deaconguard-agent")
		} else {
			fmt.Fprintln(output, "Start the agent: deaconguard agent run\nNot running as root: the deeper checks will use passwordless sudo if available.")
		}
		return nil
	case "run":
		if len(arguments) != 1 {
			return fmt.Errorf("usage: deaconguard agent run")
		}
		config, err := agent.LoadConfig(path)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return agent.Run(ctx, config, func(format string, values ...any) {
			fmt.Fprintf(diagnostics, format+"\n", values...)
		})
	case "status":
		config, err := agent.LoadConfig(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Enrolled with %s as host %s\nConfiguration: %s\n", config.ServerURL, config.HostID, path)
		return nil
	default:
		return fmt.Errorf("unknown agent action %q", arguments[0])
	}
}

// scanThroughAgent queues a scan for an agent host and waits for the server,
// which must be running, to hand it to the agent and store the result.
func scanThroughAgent(host store.Host, checks []string, asJSON bool, output, diagnostics io.Writer) error {
	if _, busy, err := store.UnfinishedScan(host.ID); err != nil {
		return err
	} else if busy {
		return fmt.Errorf("a scan is already queued or running for %s", host.Address)
	}
	record, err := store.QueueScan(host, checks)
	if err != nil {
		return err
	}
	store.Audit(local.Username()+" (cli)", "scan.start", host.Address, strings.Join(checks, ", "), "")
	fmt.Fprintf(diagnostics, "Queued scan %s for the agent on %s; the DeaconGuard server must be running to hand it over.\n", record.ID, host.Address)
	fmt.Fprintln(diagnostics, "Waiting for the result (Ctrl+C stops waiting; the scan stays queued)...")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped waiting; scan %s continues on the server", record.ID)
		case <-time.After(2 * time.Second):
		}
		current, err := store.GetScan(record.ID)
		if err != nil {
			return err
		}
		if store.IsUnfinished(current.Status) {
			continue
		}
		if current.Status != store.ScanSucceeded {
			return fmt.Errorf("scan failed: %s", current.Error)
		}
		report, err := store.GetReport(record.ID)
		if err != nil {
			return err
		}
		return showReport(report, asJSON, output)
	}
}
