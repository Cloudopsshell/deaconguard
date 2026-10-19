package cli

import (
	"bufio"
	"bytes"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"deaconguard/internal/agent"
	"deaconguard/internal/agentapi"
	"deaconguard/internal/buildinfo"
	"deaconguard/internal/local"
	"deaconguard/internal/runstate"
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
	listen, agentListen, certificatePath, keyPath := defaultListen, "", "", ""
	var proxies []string
	if configured := os.Getenv("DEACONGUARD_TRUSTED_PROXIES"); configured != "" {
		proxies = strings.Split(configured, ",")
	}
	for index := 0; index < len(arguments); index++ {
		if index+1 >= len(arguments) {
			return fmt.Errorf("usage: deaconguard serve [--listen ADDRESS:PORT] [--agent-listen ADDRESS:PORT] [--tls-cert FILE --tls-key FILE] [--trusted-proxy CIDR]...")
		}
		switch arguments[index] {
		case "--listen":
			listen = arguments[index+1]
		case "--agent-listen":
			agentListen = arguments[index+1]
		case "--tls-cert":
			certificatePath = arguments[index+1]
		case "--tls-key":
			keyPath = arguments[index+1]
		case "--trusted-proxy":
			proxies = append(proxies, arguments[index+1])
		default:
			return fmt.Errorf("unknown serve option %q", arguments[index])
		}
		index++
	}
	if (certificatePath == "") != (keyPath == "") {
		return fmt.Errorf("--tls-cert and --tls-key go together")
	}
	if err := server.SetTrustedProxies(proxies); err != nil {
		return err
	}
	if agentListen != "" {
		if _, port, err := net.SplitHostPort(agentListen); err != nil || port == "" {
			return fmt.Errorf("--agent-listen needs ADDRESS:PORT, such as 0.0.0.0:8444")
		}
		if server.IsLoopback(listen) && certificatePath == "" {
			return fmt.Errorf("--agent-listen is for a server on the network; the local dashboard has no agents")
		}
	}
	run := startRun(output)
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
		handler.StartScheduler()
		return serveUntilStopped(handler, listener, output, run, nil)
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
	if err := bootstrapAdmin(output); err != nil {
		return err
	}
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
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	listener = tls.NewListener(listener, tlsConfig)
	fmt.Fprintf(output, "DeaconGuard %s server: https://%s\n", buildinfo.Version, displayAddress(listener.Addr()))
	var agents *http.Server
	if agentListen != "" {
		// Agents get a port of their own, which serves only the agent API, so
		// the dashboard's port can be limited to the people who use it.
		agentListener, err := net.Listen("tcp", agentListen)
		if err != nil {
			listener.Close()
			return err
		}
		_, port, _ := net.SplitHostPort(agentListener.Addr().String())
		handler.SetAgentPort(port)
		agents = &http.Server{Handler: handler.AgentHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
		go func() {
			if err := agents.Serve(tls.NewListener(agentListener, tlsConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(output, "Agent listener stopped: %v\n", err)
			}
		}()
		fmt.Fprintf(output, "Agents: https://%s (the agent API only)\n", displayAddress(agentListener.Addr()))
	}
	if created {
		fmt.Fprintf(output, "Created a self-signed certificate in %s. Browsers warn about it once;\n",
			filepath.Join(store.DataDir(), "tls"))
		fmt.Fprintln(output, "agents trust it through the fingerprint in their enrollment token.")
	}
	fmt.Fprintf(output, "Certificate public key (SHA-256): %s\nData: %s\nPress Ctrl+C to stop.\n", pin, store.DatabasePath())
	handler.StartScheduler()
	return serveUntilStopped(handler, listener, output, run, agents)
}

// startRun records this run of the server and keeps how the previous run
// ended, for the dashboard and for scans it cut short. Failing to record is
// never a reason not to serve.
func startRun(output io.Writer) *runstate.Run {
	run, previous, err := runstate.Start(store.DataDir(), buildinfo.Version, time.Now())
	if err != nil {
		fmt.Fprintf(output, "Warning: cannot record this run, so a restart will not be explained: %v\n", err)
		return nil
	}
	if previous != nil && previous.Unexpected() {
		fmt.Fprintf(output, "The previous run ended unexpectedly: %s\n", previous.Message)
		if previous.Detail != "" {
			fmt.Fprintln(output, previous.Detail)
		}
		level := store.LogError
		if previous.Kind == runstate.KindReboot {
			level = store.LogWarning
		}
		message := "The previous run ended unexpectedly: " + previous.Message
		if previous.Detail != "" {
			message += "\n" + previous.Detail
		}
		store.Log(store.LogServer, "", level, message)
	}
	if err := store.SetLastStop(previous); err != nil {
		fmt.Fprintf(output, "Warning: cannot store how the previous run ended: %v\n", err)
	}
	store.Log(store.LogServer, "", store.LogInfo, fmt.Sprintf("DeaconGuard %s server started", buildinfo.Version))
	return run
}

// runRecordStop is the server service's ExecStopPost: it records how systemd
// saw the server end, for the next run to explain.
func runRecordStop() error {
	return runstate.RecordSystemdResult(store.DataDir(), os.Getenv, time.Now())
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

// serveUntilStopped serves until Ctrl+C or SIGTERM, then stops agents, the
// agent listener if there is one, first.
func serveUntilStopped(handler *server.Server, listener net.Listener, output io.Writer, run *runstate.Run, agents *http.Server) error {
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Restore default signal handling so a second Ctrl+C exits at once.
		stop()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if agents != nil {
			agents.Shutdown(shutdown)
		}
		httpServer.Shutdown(shutdown)
	}()
	if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	fmt.Fprintln(output, "Waiting for running scans to finish (press Ctrl+C again to quit now)...")
	handler.Close()
	store.Log(store.LogServer, "", store.LogInfo, "DeaconGuard server stopped")
	if run != nil {
		if err := run.Stopped(time.Now()); err != nil {
			fmt.Fprintf(output, "Warning: cannot record the stop: %v\n", err)
		}
	}
	return nil
}

func runUser(arguments []string, input io.Reader, output, diagnostics io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("user requires add, passwd, role, mfa-reset, list, or remove")
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
			state := "two-step sign-in: off"
			if user.MFAEnabled {
				state = fmt.Sprintf("two-step sign-in: on, %d recovery codes left", user.RecoveryCodesLeft)
			}
			if user.Disabled {
				state += ", disabled"
			}
			if user.MustChangePassword {
				state += ", must change password"
			}
			fmt.Fprintf(output, "%s  (%s; %s; created %s)\n", user.Username, user.Role, state, user.CreatedAt)
		}
		return nil
	case "role":
		if len(arguments) != 3 {
			return fmt.Errorf("usage: deaconguard user role USERNAME admin|operator|viewer")
		}
		user, err := store.UserByName(arguments[1])
		if err != nil {
			return err
		}
		if err := store.SetRole(user.ID, arguments[2]); err != nil {
			return err
		}
		store.Audit(local.Username()+" (cli)", "user.role", user.Username, user.Role+" to "+arguments[2]+"; signed out everywhere", "")
		fmt.Fprintf(output, "%s is now %s, and was signed out so the role applies at once.\n", user.Username, arguments[2])
		return nil
	case "mfa-reset":
		// For a lost phone when no other account can reset it in the dashboard.
		if len(arguments) != 2 {
			return fmt.Errorf("usage: deaconguard user mfa-reset USERNAME")
		}
		user, err := store.UserByName(arguments[1])
		if err != nil {
			return err
		}
		if err := store.RemoveMFA(user.ID, true); err != nil {
			return err
		}
		store.Audit(local.Username()+" (cli)", "user.mfa_reset", user.Username, "signed out everywhere", "")
		fmt.Fprintf(output, "Turned off two-step sign-in for %s and signed out their sessions. They sign in with their password, then set it up again on My account.\n", user.Username)
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
	usage := fmt.Errorf("usage: deaconguard user %s USERNAME [--password-stdin]", arguments[0])
	if arguments[0] == "add" {
		usage = fmt.Errorf("usage: deaconguard user add USERNAME [--role admin|operator|viewer] [--password-stdin]")
	}
	username, fromStdin, role := "", false, store.RoleAdmin
	for index := 1; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "--password-stdin":
			fromStdin = true
		case argument == "--role" && arguments[0] == "add" && index+1 < len(arguments):
			role = arguments[index+1]
			index++
		case strings.HasPrefix(argument, "-") || username != "":
			return usage
		default:
			username = argument
		}
	}
	if username == "" {
		return usage
	}
	if !store.ValidRole(role) {
		return store.ErrUnknownRole
	}
	password, err := readNewPassword(input, diagnostics, fromStdin)
	if err != nil {
		return err
	}
	defer clear(password)
	if arguments[0] == "add" {
		if _, err := store.AddUser(username, password, role, false); err != nil {
			return err
		}
		store.Audit(local.Username()+" (cli)", "user.add", username, role, "")
		fmt.Fprintf(output, "Created %s, with the %s role. Sign in to the dashboard served by: deaconguard serve --listen 0.0.0.0:8443\n", username, role)
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

const tokenUsage = "usage: deaconguard token create --server-url https://HOST:8443 [--reusable [--days N] [--name NAME]] [--quiet]"

func runToken(arguments []string, output io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "create" {
		return errors.New(tokenUsage)
	}
	var serverURL string
	var options store.TokenOptions
	quiet := false
	for rest := arguments[1:]; len(rest) > 0; rest = rest[1:] {
		value := func() (string, error) {
			if len(rest) < 2 {
				return "", errors.New(tokenUsage)
			}
			rest = rest[1:]
			return rest[0], nil
		}
		var err error
		switch rest[0] {
		case "--server-url":
			serverURL, err = value()
		case "--reusable":
			options.Reusable = true
		case "--name":
			options.Name, err = value()
		case "--days":
			var text string
			if text, err = value(); err == nil {
				days, convertError := strconv.Atoi(text)
				if convertError != nil || days < 1 {
					return fmt.Errorf("--days takes a number of days, from 1 to 365")
				}
				options.Lifetime = time.Duration(days) * 24 * time.Hour
			}
		case "--quiet":
			quiet = true
		default:
			return errors.New(tokenUsage)
		}
		if err != nil {
			return err
		}
	}
	if serverURL == "" {
		return errors.New(tokenUsage)
	}
	if !options.Reusable && (options.Lifetime != 0 || options.Name != "") {
		return errors.New("--days and --name are for reusable tokens: add --reusable")
	}
	serverURL = strings.TrimSuffix(strings.TrimSpace(serverURL), "/")
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
	token, secret, err := store.CreateEnrollmentToken(serverURL, local.Username()+" (cli)", options)
	if err != nil {
		return err
	}
	store.Audit(local.Username()+" (cli)", "token.create", token.ID[:8], token.Describe(), "")
	encoded := agentapi.Token{ServerURL: serverURL, Pin: pin, Secret: secret}.Encode()
	if quiet {
		fmt.Fprintln(output, encoded)
		return nil
	}
	if token.Reusable {
		fmt.Fprintf(output, "Reusable enrollment token, for any number of machines until %s:\n\n  %s\n\n", token.ExpiresAt, encoded)
		fmt.Fprintln(output, "Keep it secret: anyone with it can enroll a machine. Revoke it in the dashboard when you no longer need it.")
		fmt.Fprintf(output, "For a Kubernetes DaemonSet, store it in a secret:\n\n  kubectl -n deaconguard-agent create secret generic deaconguard-enrollment --from-literal=token='%s'\n\n", encoded)
		fmt.Fprintf(output, "Or install the agent on a machine with it:\n\n  %s\n", buildinfo.AgentInstallCommand(encoded))
		return nil
	}
	fmt.Fprintf(output, "One-time enrollment token, valid until %s:\n\n  %s\n\n", token.ExpiresAt, encoded)
	fmt.Fprintf(output, "On the machine to scan, run this as a user with sudo rights (as root, leave out \"sudo -E\"):\n\n  %s\n\n", buildinfo.AgentInstallCommand(encoded))
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
		fmt.Fprintf(output, "Enrolled %s with %s as host %s.\nSaved %s\n", config.Name(), config.ServerURL, config.HostID, path)
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
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		config, err := loadOrEnroll(ctx, path, diagnostics)
		if err != nil {
			return err
		}
		logf := func(format string, values ...any) { fmt.Fprintf(diagnostics, format+"\n", values...) }
		err = agent.Run(ctx, config, path, logf)
		// An agent with a token in its environment, such as a DaemonSet's,
		// enrolls again when the server no longer knows it: after the server
		// was reinstalled, or the host removed. Revoke the token to stop that.
		if token := enrollToken(); errors.Is(err, agent.ErrRemoved) && token != "" {
			logf("The server no longer knows this agent; enrolling again with the token from the environment.")
			if config, err = agent.Enroll(ctx, token, path, true); err != nil {
				return err
			}
			logf("Enrolled %s with %s as host %s", config.Name(), config.ServerURL, config.HostID)
			err = agent.Run(ctx, config, path, logf)
		}
		return err
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
	id, err := queueForAgent(host, checks, false, diagnostics)
	if err != nil {
		return err
	}
	report, err := waitForAgent(id)
	if err != nil {
		return err
	}
	return showReport(report, asJSON, output)
}

// queueForAgent queues a scan, or an audit, for a host's agent.
func queueForAgent(host store.Host, checks []string, isAudit bool, diagnostics io.Writer) (string, error) {
	agents, err := store.Agents()
	if err != nil {
		return "", err
	}
	for _, check := range checks {
		if version := agents[host.ID].Version; !agentapi.SupportsCheck(version, check) {
			return "", agentapi.ErrAgentTooOld(host.Address, version, check)
		}
	}
	if _, busy, err := store.UnfinishedScan(host.ID); err != nil {
		return "", err
	} else if busy {
		return "", fmt.Errorf("a scan is already queued or running for %s", host.Address)
	}
	record, err := store.QueueScan(host, checks)
	if err != nil {
		return "", err
	}
	kind, action := "scan", "scan.start"
	if isAudit {
		if err := store.MarkAudit(record.ID); err != nil {
			return "", err
		}
		kind, action = "audit", "audit.start"
	}
	store.Audit(local.Username()+" (cli)", action, host.Address, strings.Join(checks, ", "), "")
	fmt.Fprintf(diagnostics, "Queued %s %s for the agent on %s; the DeaconGuard server must be running to hand it over.\n", kind, record.ID, host.Address)
	fmt.Fprintln(diagnostics, "Waiting for the result (Ctrl+C stops waiting; it stays queued)...")
	return record.ID, nil
}

// waitForAgent waits for a queued scan to finish and returns its report.
func waitForAgent(id string) (map[string]any, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("stopped waiting; %s continues on the server", id)
		case <-time.After(2 * time.Second):
		}
		current, err := store.GetScan(id)
		if err != nil {
			return nil, err
		}
		if store.IsUnfinished(current.Status) {
			continue
		}
		if current.Status != store.ScanSucceeded {
			return nil, fmt.Errorf("the scan failed: %s", current.Error)
		}
		return store.GetReport(id)
	}
}

// bootstrapAdmin creates the first account from the environment, for
// containers, which have no setup to ask for one: DEACONGUARD_ADMIN_USER,
// and the password in the file DEACONGUARD_ADMIN_PASSWORD_FILE (such as a
// Kubernetes or Compose secret) or in DEACONGUARD_ADMIN_PASSWORD. It does
// nothing once any account exists, so the password can't be reset this way.
func bootstrapAdmin(output io.Writer) error {
	username := strings.TrimSpace(os.Getenv("DEACONGUARD_ADMIN_USER"))
	if username == "" {
		return nil
	}
	users, err := store.ListUsers()
	if err != nil || len(users) > 0 {
		return err
	}
	var password []byte
	if path := os.Getenv("DEACONGUARD_ADMIN_PASSWORD_FILE"); path != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read DEACONGUARD_ADMIN_PASSWORD_FILE: %w", err)
		}
		password = bytes.TrimRight(contents, "\r\n")
	} else {
		password = []byte(os.Getenv("DEACONGUARD_ADMIN_PASSWORD"))
	}
	defer clear(password)
	if len(password) == 0 {
		return errors.New("DEACONGUARD_ADMIN_USER is set without DEACONGUARD_ADMIN_PASSWORD_FILE or DEACONGUARD_ADMIN_PASSWORD")
	}
	if _, err := store.AddUser(username, password, store.RoleAdmin, false); err != nil {
		return fmt.Errorf("create the first account from the environment: %w", err)
	}
	store.Audit("server", "user.add", username, "admin; first account, from the environment", "")
	fmt.Fprintf(output, "Created the first account, %s, from the environment.\n", username)
	return nil
}

// enrollToken is the enrollment token in the environment, if any: in the file
// DEACONGUARD_ENROLL_TOKEN_FILE names (such as a mounted secret, which may not
// exist once every node has enrolled), or in DEACONGUARD_ENROLL_TOKEN.
func enrollToken() string {
	if file := os.Getenv("DEACONGUARD_ENROLL_TOKEN_FILE"); file != "" {
		contents, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(contents))
	}
	return strings.TrimSpace(os.Getenv("DEACONGUARD_ENROLL_TOKEN"))
}

// loadOrEnroll loads the agent's configuration or, when there is none yet
// and the environment has an enrollment token, enrolls first. That lets an
// agent in a container, such as one pod of a DaemonSet, enroll itself with a
// reusable token; see enrollToken.
func loadOrEnroll(ctx context.Context, path string, diagnostics io.Writer) (agent.Config, error) {
	config, err := agent.LoadConfig(path)
	if err == nil {
		// A token for a server with another certificate means the server
		// was replaced, such as reinstalled in a cluster: enroll with it.
		if token := enrollToken(); token != "" {
			if parsed, parseError := agentapi.ParseToken(token); parseError == nil && parsed.Pin != config.Pin {
				fmt.Fprintf(diagnostics, "The enrollment token is for a server with another certificate than %s; enrolling with it.\n", config.ServerURL)
				enrolled, enrollError := agent.Enroll(ctx, token, path, true)
				if enrollError != nil {
					fmt.Fprintf(diagnostics, "Could not enroll with the token, so keeping the enrollment with %s: %v\n", config.ServerURL, enrollError)
					return config, nil
				}
				fmt.Fprintf(diagnostics, "Enrolled %s with %s as host %s; saved %s\n", enrolled.Name(), enrolled.ServerURL, enrolled.HostID, path)
				return enrolled, nil
			}
		}
		return config, nil
	}
	if !errors.Is(err, agent.ErrNotEnrolled) {
		return config, err
	}
	token := enrollToken()
	if file := os.Getenv("DEACONGUARD_ENROLL_TOKEN_FILE"); token == "" && file != "" {
		return agent.Config{}, fmt.Errorf("this agent is not enrolled yet and has no token: create an enrollment token on the server's Agents page and put it in %s (in Kubernetes, the deaconguard-enrollment secret)", file)
	}
	if token == "" {
		return agent.Config{}, err
	}
	config, err = agent.Enroll(ctx, token, path, false)
	if err != nil {
		return agent.Config{}, err
	}
	fmt.Fprintf(diagnostics, "Enrolled %s with %s as host %s; saved %s\n", config.Name(), config.ServerURL, config.HostID, path)
	return config, nil
}
