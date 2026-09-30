// Package tlscert provides the server's HTTPS certificate: one the
// administrator supplies, or one OpsArmor creates on first start and keeps in
// its data directory. Agents pin its public key, so it is created once and
// reused rather than renewed.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	certificateFile = "server.crt"
	keyFile         = "server.key"
	// validity is long because agents trust the pinned key, not the dates;
	// browsers show a warning for a self-signed certificate either way.
	validity = 20 * 365 * 24 * time.Hour
)

// Load reads the administrator's certificate and key files.
func Load(certificatePath, keyPath string) (tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS certificate: %w", err)
	}
	return withLeaf(certificate)
}

// Ensure returns the self-signed certificate in directory, creating it if
// needed, for hostname and every address of this machine.
func Ensure(directory, hostname string) (tls.Certificate, bool, error) {
	certificatePath, keyPath := filepath.Join(directory, certificateFile), filepath.Join(directory, keyFile)
	if certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath); err == nil {
		certificate, err = withLeaf(certificate)
		return certificate, false, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, false, fmt.Errorf("load the server certificate in %s: %w", directory, err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return tls.Certificate{}, false, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, false, err
	}
	names, addresses := subjectNames(hostname)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"OpsArmor"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           addresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writePEM(certificatePath, "CERTIFICATE", der, 0o644); err != nil {
		return tls.Certificate{}, false, err
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	certificate, err = withLeaf(certificate)
	return certificate, true, err
}

func withLeaf(certificate tls.Certificate) (tls.Certificate, error) {
	if certificate.Leaf != nil {
		return certificate, nil
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func subjectNames(hostname string) ([]string, []net.IP) {
	names := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		names = append(names, hostname)
	}
	addresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if interfaces, err := net.InterfaceAddrs(); err == nil {
		for _, address := range interfaces {
			if network, ok := address.(*net.IPNet); ok && !network.IP.IsLoopback() && !network.IP.IsLinkLocalUnicast() {
				addresses = append(addresses, network.IP)
			}
		}
	}
	return names, addresses
}

func writePEM(path, kind string, der []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(file, &pem.Block{Type: kind, Bytes: der}); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
