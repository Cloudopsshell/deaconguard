package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"opsarmor/internal/store"
)

func TestHostKeyCallbackEnrollsUnknownAndRejectsRotation(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("OPSARMOR_HOME", filepath.Join(directory, "opsarmor"))
	address := "203.0.113.27"
	host := store.Host{Address: address, Username: "scanner", Port: 2222}
	firstSigner := newTestSigner(t)
	callback, err := hostKeyCallback(host)
	if err != nil {
		t.Fatal(err)
	}
	serverAddress := net.JoinHostPort(address, "2222")
	remoteAddress := &net.TCPAddr{IP: net.ParseIP(address), Port: 2222}
	err = callback(serverAddress, remoteAddress, firstSigner.PublicKey())
	unknown := new(UnknownHostKey)
	if !errors.As(err, &unknown) {
		t.Fatalf("first key callback error = %v, want UnknownHostKey", err)
	}
	if unknown.Fingerprint != ssh.FingerprintSHA256(firstSigner.PublicKey()) {
		t.Fatalf("fingerprint = %s", unknown.Fingerprint)
	}
	if !strings.HasPrefix(unknown.KnownHostsLine, "[203.0.113.27]:2222 ssh-ed25519 ") {
		t.Fatalf("known-host line = %q", unknown.KnownHostsLine)
	}
	if err := store.TrustHostKey(host, unknown.KnownHostsLine); err != nil {
		t.Fatal(err)
	}
	callback, err = hostKeyCallback(host)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback(serverAddress, remoteAddress, firstSigner.PublicKey()); err != nil {
		t.Fatalf("pinned key was rejected: %v", err)
	}
	changedSigner := newTestSigner(t)
	if err := callback(serverAddress, remoteAddress, changedSigner.PublicKey()); err == nil {
		t.Fatal("changed host key was accepted")
	}
}

func TestDefaultPortUnknownHostEntryCanBePinned(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	address := "203.0.113.28"
	host := store.Host{Address: address, Username: "scanner", Port: 22}
	signer := newTestSigner(t)
	callback, err := hostKeyCallback(host)
	if err != nil {
		t.Fatal(err)
	}
	remoteAddress := &net.TCPAddr{IP: net.ParseIP(address), Port: 22}
	err = callback(net.JoinHostPort(address, "22"), remoteAddress, signer.PublicKey())
	unknown := new(UnknownHostKey)
	if !errors.As(err, &unknown) {
		t.Fatalf("first key callback error = %v, want UnknownHostKey", err)
	}
	if err := store.TrustHostKey(host, unknown.KnownHostsLine); err != nil {
		t.Fatalf("could not pin default-port key: %v", err)
	}
}

func TestHostKeyCallbackTreatsNewAlgorithmAsUnpinnedButRejectsRotation(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	address := "203.0.113.29"
	host := store.Host{Address: address, Username: "scanner", Port: 22}
	rsaSigner := newRSATestSigner(t)
	if err := store.TrustHostKey(host, knownLine(address, rsaSigner.PublicKey())); err != nil {
		t.Fatal(err)
	}
	callback, err := hostKeyCallback(host)
	if err != nil {
		t.Fatal(err)
	}
	remoteAddress := &net.TCPAddr{IP: net.ParseIP(address), Port: 22}
	serverAddress := net.JoinHostPort(address, "22")
	edSigner := newTestSigner(t)
	err = callback(serverAddress, remoteAddress, edSigner.PublicKey())
	unknown := new(UnknownHostKey)
	if !errors.As(err, &unknown) {
		t.Fatalf("untrusted algorithm callback error = %v, want enrollment prompt", err)
	}
	if err := store.TrustHostKey(host, unknown.KnownHostsLine); err != nil {
		t.Fatal(err)
	}
	callback, err = hostKeyCallback(host)
	if err != nil {
		t.Fatal(err)
	}
	rotatedRSA := newRSATestSigner(t)
	if err := callback(serverAddress, remoteAddress, rotatedRSA.PublicKey()); err == nil {
		t.Fatal("same-algorithm rotation was accepted")
	}
}

func knownLine(address string, key ssh.PublicKey) string {
	return address + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func newRSATestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
