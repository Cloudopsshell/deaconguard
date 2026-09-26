package remote

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"opsarmor/internal/platform"
	"opsarmor/internal/store"
)

const (
	maxOSReleaseBytes = 16 * 1024
	maxPackageBytes   = 32 << 20
	maxStderrBytes    = 4 * 1024
	connectTimeout    = 45 * time.Second
	commandTimeout    = 60 * time.Second
)

type Inventory struct {
	OSRelease  string
	DPKGStatus string
	RPMQuery   string
	Kernel     string
}

type UnknownHostKey struct {
	Fingerprint    string
	KnownHostsLine string
}

func (err *UnknownHostKey) Error() string {
	return "SSH host key is not trusted; fingerprint: " + err.Fingerprint
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (buffer *limitedBuffer) Len() int       { return buffer.buffer.Len() }
func (buffer *limitedBuffer) Bytes() []byte  { return buffer.buffer.Bytes() }
func (buffer *limitedBuffer) String() string { return buffer.buffer.String() }

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	if len(value) > buffer.limit-buffer.buffer.Len() {
		return 0, fmt.Errorf("remote output exceeds %d bytes", buffer.limit)
	}
	return buffer.buffer.Write(value)
}

func Collect(host store.Host) (Inventory, error) {
	methods, cleanup, err := authenticationMethods(host)
	if err != nil {
		return Inventory{}, err
	}
	defer cleanup()
	return collectWithAuth(host, methods)
}

func CollectWithTrust(host store.Host, confirm func(*UnknownHostKey) (bool, error)) (Inventory, error) {
	methods, cleanup, err := authenticationMethods(host)
	if err != nil {
		return Inventory{}, err
	}
	defer cleanup()
	for {
		inventory, err := collectWithAuth(host, methods)
		var unknownKey *UnknownHostKey
		if !errors.As(err, &unknownKey) {
			return inventory, err
		}
		if confirm == nil {
			return Inventory{}, unknownKey
		}
		accepted, err := confirm(unknownKey)
		if err != nil {
			return Inventory{}, err
		}
		if !accepted {
			return Inventory{}, fmt.Errorf("SSH host key was not trusted; scan cancelled")
		}
		if err := store.TrustHostKey(host, unknownKey.KnownHostsLine); err != nil {
			return Inventory{}, err
		}
	}
}

func collectWithAuth(host store.Host, methods []ssh.AuthMethod) (Inventory, error) {
	client, err := connect(host, methods)
	if err != nil {
		return Inventory{}, err
	}
	defer client.Close()

	osRelease, err := run(client, "cat /etc/os-release", maxOSReleaseBytes)
	if err != nil {
		return Inventory{}, fmt.Errorf("read /etc/os-release on %s: %w", host.Address, err)
	}
	target, err := platform.Detect(string(osRelease))
	if err != nil {
		return Inventory{}, err
	}
	inventory := Inventory{OSRelease: string(osRelease)}
	if target.Family == platform.Ubuntu || target.Family == platform.Debian {
		packages, err := run(client, "head -c 33554433 /var/lib/dpkg/status", maxPackageBytes)
		if err != nil {
			return Inventory{}, fmt.Errorf("read /var/lib/dpkg/status on %s: %w", host.Address, err)
		}
		inventory.DPKGStatus = string(packages)
	} else {
		query := "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{SOURCERPM}\\t%{ARCH}\\n'"
		packages, err := run(client, query, maxPackageBytes)
		if err != nil {
			return Inventory{}, fmt.Errorf("collect installed RPM inventory on %s: %w", host.Address, err)
		}
		inventory.RPMQuery = string(packages)
	}
	kernel, err := run(client, "uname -r", 256)
	if err != nil {
		return Inventory{}, fmt.Errorf("read running kernel on %s: %w", host.Address, err)
	}
	inventory.Kernel = strings.TrimSpace(string(kernel))
	if inventory.Kernel == "" || len(inventory.Kernel) > 256 {
		return Inventory{}, fmt.Errorf("running kernel release is missing or invalid")
	}
	return inventory, nil
}

func connect(host store.Host, methods []ssh.AuthMethod) (*ssh.Client, error) {
	callback, err := hostKeyCallback(host)
	if err != nil {
		return nil, err
	}
	configuration := &ssh.ClientConfig{
		User: host.Username, Auth: methods, HostKeyCallback: callback, Timeout: connectTimeout,
	}
	address := net.JoinHostPort(host.Address, fmt.Sprint(host.Port))
	connection, err := net.DialTimeout("tcp", address, connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s within %s: %w", address, connectTimeout, err)
	}
	if err := connection.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		connection.Close()
		return nil, err
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, configuration)
	if err != nil {
		connection.Close()
		var keyError *knownhosts.KeyError
		var unknownKey *UnknownHostKey
		if errors.As(err, &unknownKey) {
			return nil, unknownKey
		}
		if errors.As(err, &keyError) {
			return nil, fmt.Errorf("SSH host key changed for %s; refusing to replace the trusted key", host.Address)
		}
		if strings.Contains(strings.ToLower(err.Error()), "unable to authenticate") {
			return nil, fmt.Errorf("SSH authentication failed for %s@%s; check the username, key authorization, and key passphrase", host.Username, host.Address)
		}
		return nil, fmt.Errorf("SSH handshake with %s failed: %w", host.Address, err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		clientConnection.Close()
		return nil, err
	}
	return ssh.NewClient(clientConnection, channels, requests), nil
}

func hostKeyCallback(host store.Host) (ssh.HostKeyCallback, error) {
	paths := []string{store.KnownHostsPath()}
	if currentUser, err := user.Current(); err == nil {
		userKnownHosts := filepath.Join(currentUser.HomeDir, ".ssh", "known_hosts")
		if userKnownHosts != paths[0] {
			if _, err := os.Stat(userKnownHosts); err == nil {
				paths = append(paths, userKnownHosts)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(paths[0]), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(paths[0], os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	callback, err := knownhosts.New(paths...)
	if err != nil {
		return nil, fmt.Errorf("load SSH known-host files: %w", err)
	}
	return func(hostname string, remoteAddress net.Addr, key ssh.PublicKey) error {
		err := callback(hostname, remoteAddress, key)
		var keyError *knownhosts.KeyError
		if errors.As(err, &keyError) {
			for _, trusted := range keyError.Want {
				if trusted.Key.Type() == key.Type() {
					return fmt.Errorf("SSH host key changed for %s using %s; refusing to replace the trusted key", host.Address, key.Type())
				}
			}
			return &UnknownHostKey{
				Fingerprint:    ssh.FingerprintSHA256(key),
				KnownHostsLine: knownhosts.Normalize(hostname) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
			}
		}
		return err
	}, nil
}

func authenticationMethods(host store.Host) ([]ssh.AuthMethod, func(), error) {
	methods := make([]ssh.AuthMethod, 0, 4)
	cleanup := func() {}
	if host.KeyPath != nil && *host.KeyPath != "" {
		path := expandHome(*host.KeyPath)
		keyData, err := os.ReadFile(path)
		if err != nil {
			return nil, cleanup, fmt.Errorf("read SSH key %s: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			var missingPassphrase *ssh.PassphraseMissingError
			if !errors.As(err, &missingPassphrase) {
				return nil, cleanup, fmt.Errorf("parse SSH key %s: %w", path, err)
			}
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return nil, cleanup, fmt.Errorf("encrypted SSH key requires an interactive passphrase prompt or an SSH agent")
			}
			fmt.Fprintf(os.Stderr, "Enter passphrase for key '%s': ", path)
			passphrase, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if readErr != nil {
				return nil, cleanup, fmt.Errorf("read SSH key passphrase: %w", readErr)
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, passphrase)
			for index := range passphrase {
				passphrase[index] = 0
			}
			if err != nil {
				return nil, cleanup, fmt.Errorf("decrypt SSH key %s: %w", path, err)
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
	} else {
		methods = append(methods, defaultKeyMethods()...)
	}
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		connection, err := net.Dial("unix", socket)
		if err == nil {
			client := agent.NewClient(connection)
			methods = append(methods, ssh.PublicKeysCallback(client.Signers))
			cleanup = func() { connection.Close() }
		}
	}
	if len(methods) == 0 {
		return nil, cleanup, fmt.Errorf("no SSH key or agent identity is available")
	}
	return methods, cleanup, nil
}

func defaultKeyMethods() []ssh.AuthMethod {
	currentUser, err := user.Current()
	if err != nil {
		return nil
	}
	methods := make([]ssh.AuthMethod, 0, 3)
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		contents, err := os.ReadFile(filepath.Join(currentUser.HomeDir, ".ssh", name))
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(contents)
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	return methods
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if currentUser, err := user.Current(); err == nil {
			return filepath.Join(currentUser.HomeDir, strings.TrimPrefix(strings.TrimPrefix(path, "~"), string(filepath.Separator)))
		}
	}
	return path
}

func run(client *ssh.Client, command string, limit int) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: maxStderrBytes}
	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Start(command); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			if stderr.Len() > 0 {
				return stdout.Bytes(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
			}
			return stdout.Bytes(), err
		}
		return stdout.Bytes(), nil
	case <-time.After(commandTimeout):
		_ = session.Close()
		return nil, fmt.Errorf("command timed out after %s", commandTimeout)
	}
}

var _ io.Writer = (*limitedBuffer)(nil)
