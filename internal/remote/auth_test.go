package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"opsarmor/internal/store"
)

const testPassword = "s3cret"

func writeKey(t *testing.T, passphrase string) (string, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(private, "test key")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "test key", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, private
}

// startAgent serves an in-memory ssh-agent. Unix socket paths are length
// limited, so the socket lives in a short directory under /tmp.
func startAgent(t *testing.T) agent.Agent {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "oa-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	keyring := agent.NewKeyring()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, connection)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", socket)
	return keyring
}

// startSSHServer runs an SSH server on localhost that answers the fixed
// inventory commands. It accepts testPassword when allowPassword is set.
func startSSHServer(t *testing.T, allowPassword bool) int {
	t.Helper()
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("no authorized keys")
		},
	}
	if allowPassword {
		config.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == testPassword {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		}
	}
	config.AddHostKey(newTestSigner(t))
	osRelease, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "rootfs", "etc", "os-release"))
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{"cat /etc/os-release": string(osRelease), "uname -r": "6.8.0-45-generic\n"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSSH(connection, config, outputs)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func serveSSH(connection net.Conn, config *ssh.ServerConfig, outputs map[string]string) {
	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		connection.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range channelRequests {
				if request.Type != "exec" || len(request.Payload) < 4 {
					request.Reply(false, nil)
					continue
				}
				command := string(request.Payload[4:])
				request.Reply(true, nil)
				output, ok := outputs[command]
				if !ok && strings.HasPrefix(command, "head -c") {
					output, ok = "Package: bash\nStatus: install ok installed\nVersion: 5.2\nArchitecture: amd64\n", true
				}
				status := uint32(0)
				if ok {
					channel.Write([]byte(output))
				} else {
					status = 127
				}
				payload := make([]byte, 4)
				binary.BigEndian.PutUint32(payload, status)
				channel.SendRequest("exit-status", false, payload)
				return
			}
		}()
	}
}

func trustAll(*UnknownHostKey) (bool, error) { return true, nil }

func TestPromptsForPassphraseAndPasswordWithRetries(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
	keyPath, _ := writeKey(t, "correct horse")
	host := store.Host{Address: "127.0.0.1", Username: "scanner", Port: startSSHServer(t, true), KeyPath: &keyPath}

	var passphraseRetries, passwordRetries []error
	inventory, err := CollectWithOptions(host, Options{
		ConfirmHostKey: trustAll,
		Passphrase: func(path string, retry error) ([]byte, error) {
			passphraseRetries = append(passphraseRetries, retry)
			if len(passphraseRetries) == 1 {
				return []byte("wrong"), nil
			}
			return []byte("correct horse"), nil
		},
		Password: func(retry error) ([]byte, error) {
			passwordRetries = append(passwordRetries, retry)
			if len(passwordRetries) == 1 {
				return []byte("wrong"), nil
			}
			return []byte(testPassword), nil
		},
	})
	if err != nil {
		t.Fatalf("CollectWithOptions() error = %v", err)
	}
	if !strings.Contains(inventory.OSRelease, "Ubuntu") || inventory.Kernel != "6.8.0-45-generic" {
		t.Fatalf("inventory = %+v", inventory)
	}
	if len(passphraseRetries) != 2 || passphraseRetries[0] != nil || passphraseRetries[1] == nil {
		t.Fatalf("passphrase prompts = %v; want a first prompt then one retry", passphraseRetries)
	}
	if len(passwordRetries) != 2 || passwordRetries[0] != nil || passwordRetries[1] == nil {
		t.Fatalf("password prompts = %v; want a first prompt then one retry", passwordRetries)
	}
}

func TestPasswordIsNotAskedWhenServerOnlyAcceptsKeys(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
	keyPath, _ := writeKey(t, "")
	host := store.Host{Address: "127.0.0.1", Username: "scanner", Port: startSSHServer(t, false), KeyPath: &keyPath}
	asked := false
	_, err := CollectWithOptions(host, Options{
		ConfirmHostKey: trustAll,
		Password:       func(error) ([]byte, error) { asked = true; return []byte(testPassword), nil },
	})
	if !errors.Is(err, ErrAuthenticationFailed) || asked {
		t.Fatalf("error = %v, password asked = %v; want authentication failure without a prompt", err, asked)
	}
}

func TestEncryptedKeyHeldByAgentIsNotPromptedFor(t *testing.T) {
	keyPath, private := writeKey(t, "correct horse")
	keyring := startAgent(t)
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	host := store.Host{Address: "203.0.113.40", Username: "scanner", Port: 22, KeyPath: &keyPath}
	keys, cleanup, err := keySigners(host, func(string, error) ([]byte, error) {
		t.Fatal("passphrase was asked although ssh-agent holds the key")
		return nil, nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	signers, err := keys()
	if err != nil || len(signers) != 1 {
		t.Fatalf("signers = %d, error = %v; want the agent identity", len(signers), err)
	}
}

func TestEncryptedKeyWithoutPromptFails(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	keyPath, _ := writeKey(t, "correct horse")
	host := store.Host{Address: "203.0.113.41", Username: "scanner", Port: 22, KeyPath: &keyPath}
	if _, _, err := keySigners(host, nil, false); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("error = %v; want passphrase error", err)
	}
}
