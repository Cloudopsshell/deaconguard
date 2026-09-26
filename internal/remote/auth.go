package remote

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"opsarmor/internal/store"
)

const maxCredentialAttempts = 3

// ErrAuthenticationFailed marks a scan the SSH server refused to log in.
var ErrAuthenticationFailed = errors.New("SSH authentication failed")

var errPasswordOffered = errors.New("the SSH server accepts password authentication")

// Options controls the interactive steps of a scan. Credentials returned by
// Passphrase and Password are used for this scan only and are never stored.
type Options struct {
	// ConfirmHostKey decides whether to trust a host key seen for the first
	// time. When nil, an untrusted key fails with *UnknownHostKey.
	ConfirmHostKey func(*UnknownHostKey) (bool, error)
	// Passphrase is asked for an encrypted key file that ssh-agent does not
	// already hold. retry explains why the previous answer was rejected.
	Passphrase func(keyPath string, retry error) ([]byte, error)
	// Password is asked when key authentication fails and the server accepts
	// passwords. When nil, password authentication is not attempted.
	Password func(retry error) ([]byte, error)
}

func Collect(host store.Host) (Inventory, error) {
	return CollectWithOptions(host, TerminalOptions(host, nil))
}

func CollectWithTrust(host store.Host, confirm func(*UnknownHostKey) (bool, error)) (Inventory, error) {
	return CollectWithOptions(host, TerminalOptions(host, confirm))
}

// TerminalOptions asks for key passphrases and passwords on the terminal.
func TerminalOptions(host store.Host, confirm func(*UnknownHostKey) (bool, error)) Options {
	return Options{ConfirmHostKey: confirm, Passphrase: terminalPassphrase, Password: terminalPassword(host)}
}

// TerminalSecret returns a prompt that reads a secret from the terminal
// without echoing it.
func TerminalSecret(prompt string) func(retry error) ([]byte, error) {
	return func(retry error) ([]byte, error) { return readSecret(prompt, retry) }
}

func CollectWithOptions(host store.Host, options Options) (Inventory, error) {
	session, err := Connect(host, options)
	if err != nil {
		return Inventory{}, err
	}
	defer session.Close()
	return session.Inventory()
}

// Connect authenticates to host, asking through options for a host-key
// decision, a key passphrase, or a password when needed.
func Connect(host store.Host, options Options) (*Session, error) {
	keys, cleanup, err := keySigners(host, options.Passphrase, options.Password != nil)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var password []byte
	defer func() { clear(password) }()
	passwordAttempts := 0
	for {
		methods, offered := authMethods(keys, password, options.Password != nil)
		client, err := connect(host, methods)
		var unknownKey *UnknownHostKey
		switch {
		case err == nil:
			return &Session{client: client, host: host}, nil
		case errors.As(err, &unknownKey):
			if options.ConfirmHostKey == nil {
				return nil, unknownKey
			}
			accepted, err := options.ConfirmHostKey(unknownKey)
			if err != nil {
				return nil, err
			}
			if !accepted {
				return nil, fmt.Errorf("SSH host key was not trusted; scan cancelled")
			}
			if err := store.TrustHostKey(host, unknownKey.KnownHostsLine); err != nil {
				return nil, err
			}
		case errors.Is(err, ErrAuthenticationFailed) && (*offered || password != nil) && options.Password != nil:
			if passwordAttempts == maxCredentialAttempts {
				return nil, fmt.Errorf("%w: the password was rejected %d times", ErrAuthenticationFailed, maxCredentialAttempts)
			}
			var retry error
			if password != nil {
				retry = errors.New("the server rejected that password")
			}
			clear(password)
			if password, err = options.Password(retry); err != nil {
				return nil, err
			}
			passwordAttempts++
		default:
			return nil, err
		}
	}
}

// authMethods tries every key first, then a password. Without a password,
// a probe records whether the server would accept one so it can be asked for.
func authMethods(keys func() ([]ssh.Signer, error), password []byte, askPassword bool) ([]ssh.AuthMethod, *bool) {
	offered := new(bool)
	methods := []ssh.AuthMethod{ssh.PublicKeysCallback(keys)}
	switch {
	case password != nil:
		secret := string(password)
		methods = append(methods, ssh.Password(secret), ssh.KeyboardInteractive(
			func(_, _ string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for index := range questions {
					if !echos[index] {
						answers[index] = secret
					}
				}
				return answers, nil
			}))
	case askPassword:
		methods = append(methods,
			ssh.PasswordCallback(func() (string, error) {
				*offered = true
				return "", errPasswordOffered
			}),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				if len(questions) == 0 {
					return nil, nil
				}
				*offered = true
				return nil, errPasswordOffered
			}))
	}
	return methods, offered
}

// keySigners loads the host's key file, or the default keys, plus ssh-agent
// identities. All are offered through one publickey method because the SSH
// client tries each method name only once.
func keySigners(host store.Host, passphraseFor func(string, error) ([]byte, error), passwordAllowed bool) (func() ([]ssh.Signer, error), func(), error) {
	cleanup := func() {}
	var fileSigners []ssh.Signer
	socket := os.Getenv("SSH_AUTH_SOCK")
	if host.KeyPath != nil && *host.KeyPath != "" {
		path := expandHome(*host.KeyPath)
		signer, err := loadKey(path, socket, passphraseFor)
		if err != nil {
			return nil, cleanup, err
		}
		if signer != nil {
			fileSigners = append(fileSigners, signer)
		}
	} else {
		fileSigners = defaultKeySigners()
	}
	var agentClient agent.ExtendedAgent
	if socket != "" {
		if connection, err := net.Dial("unix", socket); err == nil {
			agentClient = agent.NewClient(connection)
			cleanup = func() { connection.Close() }
		}
	}
	if len(fileSigners) == 0 && agentClient == nil && !passwordAllowed {
		return nil, cleanup, fmt.Errorf("no SSH key or agent identity is available")
	}
	return func() ([]ssh.Signer, error) {
		signers := append([]ssh.Signer(nil), fileSigners...)
		if agentClient != nil {
			if agentSigners, err := agentClient.Signers(); err == nil {
				signers = append(signers, agentSigners...)
			}
		}
		return signers, nil
	}, cleanup, nil
}

// loadKey parses a private key file. An encrypted key that ssh-agent already
// holds returns nil so the agent signs instead of asking for the passphrase.
func loadKey(path, socket string, passphraseFor func(string, error) ([]byte, error)) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	var missingPassphrase *ssh.PassphraseMissingError
	if err == nil {
		return signer, nil
	}
	if !errors.As(err, &missingPassphrase) {
		return nil, fmt.Errorf("parse SSH key %s: %w", path, err)
	}
	if missingPassphrase.PublicKey != nil && agentHoldsKey(socket, missingPassphrase.PublicKey) {
		return nil, nil
	}
	if passphraseFor == nil {
		return nil, fmt.Errorf("SSH key %s is protected by a passphrase and is not loaded in ssh-agent", path)
	}
	var retry error
	for attempt := 0; attempt < maxCredentialAttempts; attempt++ {
		passphrase, err := passphraseFor(path, retry)
		if err != nil {
			return nil, err
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, passphrase)
		clear(passphrase)
		if err == nil {
			return signer, nil
		}
		if !errors.Is(err, x509.IncorrectPasswordError) {
			return nil, fmt.Errorf("decrypt SSH key %s: %w", path, err)
		}
		retry = errors.New("incorrect passphrase")
	}
	return nil, fmt.Errorf("decrypt SSH key %s: the passphrase was incorrect %d times", path, maxCredentialAttempts)
}

// agentHoldsKey reports whether the ssh-agent at socket offers key.
func agentHoldsKey(socket string, key ssh.PublicKey) bool {
	if socket == "" {
		return false
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		return false
	}
	defer connection.Close()
	identities, err := agent.NewClient(connection).List()
	if err != nil {
		return false
	}
	for _, identity := range identities {
		if bytes.Equal(identity.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

func defaultKeySigners() []ssh.Signer {
	currentUser, err := user.Current()
	if err != nil {
		return nil
	}
	signers := make([]ssh.Signer, 0, 3)
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		contents, err := os.ReadFile(filepath.Join(currentUser.HomeDir, ".ssh", name))
		if err != nil {
			continue
		}
		if signer, err := ssh.ParsePrivateKey(contents); err == nil {
			signers = append(signers, signer)
		}
	}
	return signers
}

func terminalPassphrase(path string, retry error) ([]byte, error) {
	return readSecret(fmt.Sprintf("Enter passphrase for key '%s': ", path), retry)
}

func terminalPassword(host store.Host) func(error) ([]byte, error) {
	return func(retry error) ([]byte, error) {
		return readSecret(fmt.Sprintf("%s@%s's password: ", host.Username, host.Address), retry)
	}
}

func readSecret(prompt string, retry error) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("a passphrase or password is required; run the scan in a terminal or load the key into ssh-agent")
	}
	if retry != nil {
		fmt.Fprintf(os.Stderr, "%s. ", retry)
	}
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return secret, nil
}
