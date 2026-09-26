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
	"golang.org/x/crypto/ssh/knownhosts"

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

// Session is an authenticated connection to a registered host. Callers run
// only fixed, read-only commands defined in OpsArmor's source.
type Session struct {
	client   *ssh.Client
	host     store.Host
	observer CommandObserver
}

// CommandObserver is told about every command a session runs, for live
// progress. It never receives command input, which can hold a sudo password.
type CommandObserver interface {
	CommandStarted(command string)
	CommandFinished(command string, outputBytes int, elapsed time.Duration, err error)
}

// Observe reports every later command on this session to observer.
func (s *Session) Observe(observer CommandObserver) { s.observer = observer }

func (s *Session) Host() store.Host { return s.host }

func (s *Session) Close() error { return s.client.Close() }

// Run executes command, feeding stdin if it is not nil, and returns at most
// limit bytes of output. Output read before a non-zero exit is returned
// alongside the error, which wraps *ssh.ExitError.
func (s *Session) Run(command string, stdin []byte, limit int, timeout time.Duration) ([]byte, error) {
	if s.observer == nil {
		return run(s.client, command, stdin, limit, timeout)
	}
	s.observer.CommandStarted(command)
	started := time.Now()
	output, err := run(s.client, command, stdin, limit, timeout)
	s.observer.CommandFinished(command, len(output), time.Since(started), err)
	return output, err
}

// OSRelease reads /etc/os-release.
func (s *Session) OSRelease() (string, error) {
	osRelease, err := s.Run("cat /etc/os-release", nil, maxOSReleaseBytes, commandTimeout)
	if err != nil {
		return "", fmt.Errorf("read /etc/os-release on %s: %w", s.host.Address, err)
	}
	return string(osRelease), nil
}

// Inventory collects the OS release, installed packages, and running kernel.
func (s *Session) Inventory() (Inventory, error) {
	host := s.host
	osRelease, err := s.OSRelease()
	if err != nil {
		return Inventory{}, err
	}
	if err != nil {
		return Inventory{}, fmt.Errorf("read /etc/os-release on %s: %w", host.Address, err)
	}
	target, err := platform.Detect(osRelease)
	if err != nil {
		return Inventory{}, err
	}
	inventory := Inventory{OSRelease: osRelease}
	if target.Family == platform.Ubuntu || target.Family == platform.Debian {
		packages, err := s.Run("head -c 33554433 /var/lib/dpkg/status", nil, maxPackageBytes, commandTimeout)
		if err != nil {
			return Inventory{}, fmt.Errorf("read /var/lib/dpkg/status on %s: %w", host.Address, err)
		}
		inventory.DPKGStatus = string(packages)
	} else {
		query := "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{SOURCERPM}\\t%{ARCH}\\n'"
		packages, err := s.Run(query, nil, maxPackageBytes, commandTimeout)
		if err != nil {
			return Inventory{}, fmt.Errorf("collect installed RPM inventory on %s: %w", host.Address, err)
		}
		inventory.RPMQuery = string(packages)
	}
	kernel, err := s.Run("uname -r", nil, 256, commandTimeout)
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
		if strings.Contains(strings.ToLower(err.Error()), "unable to authenticate") || errors.Is(err, errPasswordOffered) {
			return nil, fmt.Errorf("%w for %s@%s; check the username and that the key or password is authorized",
				ErrAuthenticationFailed, host.Username, host.Address)
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

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if currentUser, err := user.Current(); err == nil {
			return filepath.Join(currentUser.HomeDir, strings.TrimPrefix(strings.TrimPrefix(path, "~"), string(filepath.Separator)))
		}
	}
	return path
}

func run(client *ssh.Client, command string, stdin []byte, limit int, timeout time.Duration) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	if stdin != nil {
		session.Stdin = bytes.NewReader(stdin)
	}
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
	case <-time.After(timeout):
		_ = session.Close()
		return nil, fmt.Errorf("command timed out after %s", timeout)
	}
}

var _ io.Writer = (*limitedBuffer)(nil)
