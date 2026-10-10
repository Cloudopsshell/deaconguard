package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"deaconguard/internal/agent"
	"deaconguard/internal/agentapi"
	"deaconguard/internal/local"
	"deaconguard/internal/store"
)

// deaconguard setup configures and starts the services installed by the
// .deb and .rpm packages. install.sh runs it after installing the package, and
// again on every upgrade, so each step leaves a finished setup alone.

const (
	serviceAccount      = "deaconguard"
	serverUnit          = "deaconguard-server.service"
	agentUnit           = "deaconguard-agent.service"
	unitDirectory       = "/usr/lib/systemd/system"
	defaultServerListen = "0.0.0.0:8443"
	// The packaged unit runs the server on defaultServerListen with its own
	// certificate; other settings go in a drop-in that survives upgrades.
	serverDropIn = "/etc/systemd/system/deaconguard-server.service.d/10-setup.conf"
	// noAccountsMessage starts the output of `user list` when there are none.
	noAccountsMessage = "No dashboard accounts."
)

type serverSetup struct {
	listen, certificate, key string
	adminUser, passwordFile  string
}

type agentSetup struct {
	tokenFile string
	force     bool
}

func runSetup(arguments []string, output, diagnostics io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("setup requires server or agent")
	}
	switch arguments[0] {
	case "server":
		options, err := parseServerSetup(arguments[1:])
		if err != nil {
			return err
		}
		return setupServer(options, output, diagnostics)
	case "agent":
		options, err := parseAgentSetup(arguments[1:])
		if err != nil {
			return err
		}
		return setupAgent(options, output, diagnostics)
	default:
		return fmt.Errorf("unknown setup target %q; use server or agent", arguments[0])
	}
}

const (
	serverSetupUsage = "usage: deaconguard setup server [--listen ADDRESS:PORT] [--tls-cert FILE --tls-key FILE] [--admin-user NAME] [--admin-password-file FILE]"
	agentSetupUsage  = "usage: deaconguard setup agent [--token-file FILE] [--force]"
)

func parseServerSetup(arguments []string) (serverSetup, error) {
	var options serverSetup
	for index := 0; index < len(arguments); index++ {
		if index+1 >= len(arguments) {
			return options, errors.New(serverSetupUsage)
		}
		value := arguments[index+1]
		switch arguments[index] {
		case "--listen":
			options.listen = value
		case "--tls-cert":
			options.certificate = value
		case "--tls-key":
			options.key = value
		case "--admin-user":
			options.adminUser = value
		case "--admin-password-file":
			options.passwordFile = value
		default:
			return options, fmt.Errorf("unknown setup server option %q\n%s", arguments[index], serverSetupUsage)
		}
		index++
	}
	if (options.certificate == "") != (options.key == "") {
		return options, fmt.Errorf("--tls-cert and --tls-key go together")
	}
	for _, path := range []string{options.certificate, options.key} {
		if path != "" && !filepath.IsAbs(path) {
			return options, fmt.Errorf("%s must be an absolute path, because the service does not run in this directory", path)
		}
	}
	if options.listen != "" {
		if _, port, err := net.SplitHostPort(options.listen); err != nil || port == "" {
			return options, fmt.Errorf("--listen needs ADDRESS:PORT, such as 0.0.0.0:8443")
		}
		if isLoopbackListen(options.listen) {
			return options, fmt.Errorf("the server must listen on the network for agents to reach it; for a dashboard on this machine only, run: deaconguard serve")
		}
	}
	return options, nil
}

func parseAgentSetup(arguments []string) (agentSetup, error) {
	var options agentSetup
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--force":
			options.force = true
		case "--token-file":
			if index+1 >= len(arguments) {
				return options, errors.New(agentSetupUsage)
			}
			options.tokenFile = arguments[index+1]
			index++
		default:
			// A token on the command line would be visible to every user in
			// the process list and kept in the shell's history.
			if strings.HasPrefix(arguments[index], "deaconguard1.") {
				return options, fmt.Errorf("do not pass the token on the command line; enter it when asked, or use --token-file FILE or DEACONGUARD_TOKEN")
			}
			return options, fmt.Errorf("unknown setup agent option %q\n%s", arguments[index], agentSetupUsage)
		}
	}
	return options, nil
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// renderServerDropIn returns the drop-in that runs the server with options, or
// "" when the packaged unit's defaults apply.
func renderServerDropIn(listen, certificate, key string) string {
	if listen == defaultServerListen && certificate == "" {
		return ""
	}
	command := "/usr/bin/deaconguard serve --listen " + listen
	if certificate != "" {
		command += " --tls-cert " + certificate + " --tls-key " + key
	}
	return "# Written by deaconguard setup server; run it again to change these settings.\n" +
		"[Service]\nExecStart=\nExecStart=" + command + "\n"
}

var dropInSetting = regexp.MustCompile(`--(listen|tls-cert|tls-key) (\S+)`)

// parseServerDropIn reads the settings back from a drop-in written by
// renderServerDropIn, so running setup again without options keeps them.
func parseServerDropIn(contents string) (listen, certificate, key string) {
	listen = defaultServerListen
	for _, line := range strings.Split(contents, "\n") {
		if !strings.HasPrefix(line, "ExecStart=/") {
			continue
		}
		for _, match := range dropInSetting.FindAllStringSubmatch(line, -1) {
			switch match[1] {
			case "listen":
				listen = match[2]
			case "tls-cert":
				certificate = match[2]
			case "tls-key":
				key = match[2]
			}
		}
	}
	return listen, certificate, key
}

// checkServiceHost stops setup early where it cannot work: it changes system
// services, so it needs root, systemd, and the unit from the package.
func checkServiceHost(unit string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup configures system services; run it with sudo")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("setup needs systemd, which is not running on this machine")
	}
	if _, err := os.Stat(filepath.Join(unitDirectory, unit)); err != nil {
		return fmt.Errorf("%s is not installed; install the DeaconGuard .deb or .rpm package first", unit)
	}
	return nil
}

// startService enables unit and makes sure it runs this setup's
// configuration. A service that is already running is left alone unless
// changed: on an upgrade, the package has just restarted it with the new
// version, and a second restart would only interrupt it again.
func startService(unit string, changed bool, output io.Writer) error {
	if err := systemctl("enable", unit); err != nil {
		return err
	}
	if !changed && serviceActive(unit) {
		fmt.Fprintf(output, "%s is running the installed version; no restart needed.\n", unit)
		return nil
	}
	return systemctl("restart", unit)
}

// serviceActive reports whether unit is running.
func serviceActive(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

func systemctl(arguments ...string) error {
	combined, err := exec.Command("systemctl", arguments...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(combined)))
	}
	return nil
}

func setupServer(options serverSetup, output, diagnostics io.Writer) error {
	if err := checkServiceHost(serverUnit); err != nil {
		return err
	}
	account, err := user.Lookup(serviceAccount)
	if err != nil {
		return fmt.Errorf("the %s user does not exist; reinstall the package to create it", serviceAccount)
	}

	// Settings: those given now, otherwise the ones from an earlier setup.
	existing, err := os.ReadFile(serverDropIn)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listen, certificate, key := parseServerDropIn(string(existing))
	if options.listen != "" {
		listen = options.listen
	}
	if options.certificate != "" {
		certificate, key = options.certificate, options.key
	}
	// changed is whether this setup changed something the running server
	// must restart to pick up.
	changed := false
	if dropIn := renderServerDropIn(listen, certificate, key); dropIn != string(existing) {
		changed = true
		if dropIn == "" {
			err = os.Remove(serverDropIn)
		} else if err = os.MkdirAll(filepath.Dir(serverDropIn), 0o755); err == nil {
			err = os.WriteFile(serverDropIn, []byte(dropIn), 0o644)
		}
		if err != nil {
			return fmt.Errorf("save the server settings: %w", err)
		}
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
	}

	// The server will not start on the network without a dashboard account.
	accounts, err := runAsService(account, nil, "user", "list")
	if err != nil {
		return err
	}
	if strings.HasPrefix(accounts, noAccountsMessage) {
		if err := createFirstAccount(account, options, output, diagnostics); err != nil {
			return err
		}
		changed = true
	} else {
		fmt.Fprintln(output, "Dashboard accounts already exist; keeping them.")
	}

	if err := startService(serverUnit, changed, output); err != nil {
		return err
	}
	if err := waitForServer(listen); err != nil {
		return fmt.Errorf("%w\nSee what happened: journalctl -u %s -n 30", err, serverUnit)
	}
	if certificate == "" {
		certificate = filepath.Join(store.SystemDataDir, "tls", "server.crt")
	}
	pin, err := certificatePin(certificate)
	if err != nil {
		return err
	}

	_, port, _ := net.SplitHostPort(listen)
	fmt.Fprintf(output, "\nThe DeaconGuard server is running. Open the dashboard and sign in:\n\n")
	for _, address := range serverAddresses(listen) {
		fmt.Fprintf(output, "  https://%s\n", net.JoinHostPort(address, port))
	}
	fmt.Fprintf(output, "\nCertificate public key (SHA-256): %s\n", pin)
	if options.certificate == "" && strings.HasPrefix(certificate, store.SystemDataDir) {
		fmt.Fprintln(output, "The certificate is self-signed, so the browser warns about it once. Agents trust it\nthrough this fingerprint, which every enrollment token carries.")
	}
	fmt.Fprintf(output, "\nAdd machines on the dashboard's Agents page. Only allow port %s from the\nnetworks of your administrators and agents.\n", port)
	return nil
}

// createFirstAccount asks for, or reads, the first dashboard account and
// creates it as the service account, which owns the server's data.
func createFirstAccount(account *user.User, options serverSetup, output, diagnostics io.Writer) error {
	username := options.adminUser
	var password []byte
	if options.passwordFile != "" {
		contents, err := os.ReadFile(options.passwordFile)
		if err != nil {
			return err
		}
		password = bytes.TrimRight(contents, "\r\n")
		if err := store.ValidatePassword(password); err != nil {
			clear(password)
			return err
		}
	}
	if username == "" || password == nil {
		terminal, closeTerminal, err := openTerminal()
		if err != nil {
			return fmt.Errorf("create the first dashboard account: %w; or pass --admin-user NAME --admin-password-file FILE", err)
		}
		defer closeTerminal()
		fmt.Fprintln(diagnostics, "Create the first dashboard account. It can sign in from any browser that reaches this server.")
		if username == "" {
			fmt.Fprint(diagnostics, "Username [admin]: ")
			line, err := bufio.NewReader(terminal).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if username = strings.TrimSpace(line); username == "" {
				username = "admin"
			}
		}
		if err := store.ValidateUsername(username); err != nil {
			return err
		}
		if password == nil {
			if password, err = promptNewPassword(terminal, diagnostics); err != nil {
				return err
			}
		}
	}
	defer clear(password)
	if err := store.ValidateUsername(username); err != nil {
		return err
	}
	input := append(append([]byte{}, password...), '\n')
	defer clear(input)
	if _, err := runAsService(account, input, "user", "add", username, "--password-stdin"); err != nil {
		return err
	}
	fmt.Fprintf(output, "Created the dashboard account %s.\n", username)
	return nil
}

// runAsService runs this binary as the service account, which must own the
// server's database; root is refused to keep the files it creates out of it.
func runAsService(account *user.User, input []byte, arguments ...string) (string, error) {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return "", err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return "", err
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	command := exec.Command(executable, arguments...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + store.SystemDataDir}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimPrefix(strings.TrimSpace(stderr.String()), "deaconguard: ")
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("deaconguard %s: %s", arguments[0]+" "+arguments[1], message)
	}
	return stdout.String(), nil
}

// waitForServer waits for the service to accept connections on listen.
func waitForServer(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, port)
	deadline := time.Now().Add(30 * time.Second)
	for {
		// A full handshake, so the server does not log an aborted one. Nothing
		// is trusted here: setup reads the fingerprint from the certificate file.
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{InsecureSkipVerify: true}}
		connection, err := dialer.Dial("tcp", address)
		if err == nil {
			connection.Close()
			// A server that exits right after listening is not running.
			if exec.Command("systemctl", "is-active", "--quiet", serverUnit).Run() == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the server did not start listening on %s within 30 seconds", address)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func certificatePin(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the server certificate: %w", err)
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s does not start with a PEM certificate", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return agentapi.PublicKeyPin(certificate), nil
}

// serverAddresses lists the names a browser can use to reach a server
// listening on listen: the address itself, or the hostname and every
// non-loopback address when it listens on all of them.
func serverAddresses(listen string) []string {
	host, _, err := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); err != nil || host == "" || ip == nil || !ip.IsUnspecified() {
		return []string{host}
	}
	addresses := []string{local.Hostname()}
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return addresses
	}
	for _, address := range interfaceAddresses {
		network, ok := address.(*net.IPNet)
		if !ok || network.IP.IsLoopback() || network.IP.IsLinkLocalUnicast() {
			continue
		}
		if network.IP.To4() != nil || host == "::" {
			addresses = append(addresses, network.IP.String())
		}
	}
	return addresses
}

func setupAgent(options agentSetup, output, diagnostics io.Writer) error {
	if err := checkServiceHost(agentUnit); err != nil {
		return err
	}
	path := agent.SystemConfigPath
	token, err := agentToken(options)
	if err != nil {
		return err
	}
	current, loadErr := agent.LoadConfig(path)
	enrolled := loadErr == nil
	// changed is whether this setup enrolled the machine, which the running
	// agent must restart to pick up.
	changed := false
	switch {
	case enrolled && token == "" && !options.force:
		fmt.Fprintf(output, "Already enrolled with %s as host %s; keeping it.\n", current.ServerURL, current.HostID)
	case enrolled && !options.force:
		return fmt.Errorf("this machine is already enrolled with %s; add --force to enroll it again with the new token", current.ServerURL)
	default:
		if token == "" {
			terminal, closeTerminal, err := openTerminal()
			if err != nil {
				return fmt.Errorf("enroll this machine: %w; or pass --token-file FILE, or set DEACONGUARD_TOKEN", err)
			}
			defer closeTerminal()
			fmt.Fprint(diagnostics, "Enrollment token (from the server's Agents page; hidden while you paste): ")
			secret, err := term.ReadPassword(int(terminal.Fd()))
			fmt.Fprintln(diagnostics)
			if err != nil {
				return fmt.Errorf("read the token: %w", err)
			}
			token = strings.TrimSpace(string(secret))
			clear(secret)
		}
		// An unreadable or incomplete configuration is replaced.
		config, err := agent.Enroll(context.Background(), token, path, options.force || !enrolled)
		if err != nil {
			return err
		}
		fmt.Fprintf(output, "Enrolled %s with %s as host %s.\n", local.Hostname(), config.ServerURL, config.HostID)
		changed = true
	}

	if err := startService(agentUnit, changed, output); err != nil {
		return err
	}
	// The agent exits soon if the server rejects it; give it a moment.
	time.Sleep(3 * time.Second)
	if exec.Command("systemctl", "is-active", "--quiet", agentUnit).Run() != nil {
		return fmt.Errorf("the agent service stopped after starting; see what happened: journalctl -u %s -n 30", agentUnit)
	}
	fmt.Fprintln(output, "The DeaconGuard agent is running. This machine appears on the server's Agents page.")
	return nil
}

// agentToken reads the token from --token-file or DEACONGUARD_TOKEN; "" means
// neither was given.
func agentToken(options agentSetup) (string, error) {
	if options.tokenFile != "" {
		contents, err := os.ReadFile(options.tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(contents)), nil
	}
	return strings.TrimSpace(os.Getenv("DEACONGUARD_TOKEN")), nil
}

// openTerminal returns the terminal to prompt on. With `curl ... | sudo sh`,
// standard input is the script, so the prompt reads from /dev/tty instead.
func openTerminal() (*os.File, func(), error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, func() {}, nil
	}
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil || !term.IsTerminal(int(terminal.Fd())) {
		if terminal != nil {
			terminal.Close()
		}
		return nil, nil, errors.New("no terminal to ask on")
	}
	return terminal, func() { terminal.Close() }, nil
}
