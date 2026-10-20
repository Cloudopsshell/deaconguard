package netscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/iac"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// serveTLS serves TLS with a certificate for name, valid until notAfter,
// and the given settings; it returns the address and the certificate.
func serveTLS(t *testing.T, name string, notAfter time.Time, rsaBits int, config *tls.Config) (string, *x509.Certificate) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	var key any
	var public any
	if rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		key, public = k, &k.PublicKey
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, public = k, &k.PublicKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	config.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()
	return listener.Addr().String(), cert
}

func rules(findings []iac.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.Rule)
	}
	slices.Sort(ids)
	return ids
}

func TestModernTLSIsClean(t *testing.T) {
	address, cert := serveTLS(t, "shop.example", now.Add(200*24*time.Hour), 0, &tls.Config{MinVersion: tls.VersionTLS12})
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	info, findings, err := CheckTLS(context.Background(), address, "shop.example", roots, now, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 || !info.Trusted || !slices.Equal(info.Protocols, []string{"TLS 1.2", "TLS 1.3"}) {
		t.Fatalf("info %+v, findings %+v", info, findings)
	}
}

func TestWeakTLSIsReported(t *testing.T) {
	// A self-signed 1024-bit RSA certificate for another name, expiring in
	// ten days, on a server that accepts TLS 1.0 and 3DES and not TLS 1.3.
	config := &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256}}
	address, _ := serveTLS(t, "other.example", now.Add(10*24*time.Hour), 1024, config)
	_, findings, err := CheckTLS(context.Background(), address, "shop.example", x509.NewCertPool(), now, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := rules(findings)
	for _, want := range []string{"DG-TLS-002", "DG-TLS-004", "DG-TLS-005", "DG-TLS-006", "DG-TLS-007", "DG-TLS-008", "DG-TLS-010", "DG-TLS-011"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s in %v", want, got)
		}
	}
	for _, f := range findings {
		if f.Rule == "DG-TLS-007" && (!strings.Contains(f.Title, "3DES") || strings.Contains(f.Title, "AES")) {
			t.Errorf("weak ciphers: %s", f.Title)
		}
	}
	expired, _ := serveTLS(t, "old.example", now.Add(-time.Hour), 0, &tls.Config{})
	_, findings, _ = CheckTLS(context.Background(), expired, "old.example", x509.NewCertPool(), now, 2*time.Second)
	if got := rules(findings); !slices.Contains(got, "DG-TLS-001") || slices.Contains(got, "DG-TLS-004") {
		t.Errorf("expired: %v (expiry is reported, not trust)", got)
	}
	if _, _, err := CheckTLS(context.Background(), "127.0.0.1:1", "", nil, now, time.Second); err == nil {
		t.Error("a closed port")
	}
}

func TestScanFindsServices(t *testing.T) {
	// A service that greets, like SSH.
	greeter, _ := net.Listen("tcp", "127.0.0.1:0")
	defer greeter.Close()
	go func() {
		for {
			conn, err := greeter.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			conn.Close()
		}
	}()
	tlsAddress, _ := serveTLS(t, "x", now.Add(100*24*time.Hour), 0, &tls.Config{MinVersion: tls.VersionTLS12})
	greeterPort := greeter.Addr().(*net.TCPAddr).Port
	_, tlsPortText, _ := net.SplitHostPort(tlsAddress)
	tlsPort, _ := strconv.Atoi(tlsPortText)
	ports := []int{greeterPort, tlsPort, closedPort(t)}
	// A real Redis port, when free, to check the rule.
	if redis, err := net.Listen("tcp", "127.0.0.1:6379"); err == nil {
		defer redis.Close()
		go func() {
			for {
				conn, err := redis.Accept()
				if err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
				conn.Close()
			}
		}()
		ports = append(ports, 6379)
	}
	result := Scan(context.Background(), []Target{{Address: netip.MustParseAddr("127.0.0.1")}}, Options{Ports: ports, Timeout: time.Second, TLS: true, Now: now})
	if len(result.Hosts) != 1 {
		t.Fatalf("hosts %+v", result.Hosts)
	}
	found := map[int]Service{}
	for _, service := range result.Hosts[0].Services {
		found[service.Port] = service
	}
	if found[greeterPort].Banner != "SSH-2.0-OpenSSH_9.6" || !found[tlsPort].TLS || len(found) != len(ports)-1 {
		t.Fatalf("services %+v", result.Hosts[0].Services)
	}
	if len(result.TLS) != 1 || !slices.Contains(rules(result.Findings), "DG-TLS-004") {
		t.Errorf("TLS %+v findings %v", result.TLS, rules(result.Findings))
	}
	if slices.Contains(ports, 6379) && !slices.Contains(rules(result.Findings), "DG-NET-001") {
		t.Errorf("Redis not reported: %v", rules(result.Findings))
	}
}

func closedPort(t *testing.T) int {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestParsing(t *testing.T) {
	ports, err := ParsePorts("443, 22,8000-8002,22")
	if err != nil || !slices.Equal(ports, []int{22, 443, 8000, 8001, 8002}) {
		t.Errorf("ports %v %v", ports, err)
	}
	for _, bad := range []string{"0", "70000", "9-3", "x"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ports %q accepted", bad)
		}
	}
	targets, err := ParseTargets(context.Background(), []string{"10.0.0.0/30", "10.0.0.1", "192.168.1.5"}, 100)
	if err != nil || len(targets) != 3 || targets[0].Address.String() != "10.0.0.1" || targets[1].Address.String() != "10.0.0.2" {
		t.Errorf("targets %v %v", targets, err)
	}
	if _, err := ParseTargets(context.Background(), []string{"10.0.0.0/24"}, 100); err == nil {
		t.Error("more than max addresses accepted")
	}
	if _, err := ParseTargets(context.Background(), []string{"10.0.0.0/8"}, 1<<20); err == nil {
		t.Error("a /8 accepted")
	}
	if len(Rules()) != len(netRules)+len(tlsRules) {
		t.Error("Rules")
	}
}
