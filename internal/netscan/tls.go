// Package netscan checks network services from the outside, as an attacker
// would see them, without logging in or sending anything but handshakes:
// TLS certificates and protocol settings, and, for networks you name, which
// ports are open and what answers on them. It never exploits, guesses
// passwords or floods: connections are plain TCP connects, rate-limited.
package netscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"deaconguard/internal/iac"
)

// Rule describes a rule, for documentation.
type Rule struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

var tlsRules = []Rule{
	{"DG-TLS-001", "CRITICAL", "The certificate has expired"},
	{"DG-TLS-002", "HIGH", "The certificate expires within 14 days"},
	{"DG-TLS-003", "MEDIUM", "The certificate expires within 30 days"},
	{"DG-TLS-004", "MEDIUM", "The certificate isn't trusted (self-signed or an unknown authority)"},
	{"DG-TLS-005", "HIGH", "The certificate doesn't name the host"},
	{"DG-TLS-006", "HIGH", "TLS 1.0 or 1.1 is accepted"},
	{"DG-TLS-007", "MEDIUM", "A broken cipher suite is accepted (3DES, RC4)"},
	{"DG-TLS-008", "MEDIUM", "The certificate's key is too short"},
	{"DG-TLS-009", "MEDIUM", "The certificate is signed with SHA-1"},
	{"DG-TLS-010", "LOW", "TLS 1.3 isn't offered"},
	{"DG-TLS-011", "LOW", "Cipher suites without forward secrecy are accepted"},
}

// allSuites offers every suite Go knows, so old servers can be examined.
func allSuites() []uint16 {
	var ids []uint16
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		ids = append(ids, suite.ID)
	}
	return ids
}

func ruleSeverity(id string) string {
	for _, rule := range append(append(append([]Rule{}, tlsRules...), netRules...), webRules...) {
		if rule.ID == id {
			return rule.Severity
		}
	}
	return "MEDIUM"
}

func finding(id, target, title, detail string) iac.Finding {
	return iac.Finding{Rule: id, Severity: ruleSeverity(id), Title: title, Detail: detail, File: target, Line: 1}
}

// TLSInfo is what a TLS check read of a service.
type TLSInfo struct {
	Target    string    `json:"target"`
	Version   string    `json:"version"`
	Cipher    string    `json:"cipher"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	NotAfter  time.Time `json:"not_after"`
	Trusted   bool      `json:"trusted"`
	Protocols []string  `json:"protocols"`
}

// handshake tries one TLS handshake and returns the connection state.
func handshake(ctx context.Context, address, serverName string, config *tls.Config, timeout time.Duration) (tls.ConnectionState, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: config}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState(), nil
}

// CheckTLS checks a TLS service: its certificate, which TLS versions it
// accepts and whether it accepts weak cipher suites. target is host:port;
// serverName, if set, is the name the certificate must carry (SNI).
func CheckTLS(ctx context.Context, target, serverName string, roots *x509.CertPool, now time.Time, timeout time.Duration) (TLSInfo, []iac.Finding, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return TLSInfo{}, nil, fmt.Errorf("%s: give host:port", target)
	}
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}
	// The first handshake accepts any certificate, so it can be examined.
	state, err := handshake(ctx, target, serverName, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, //nolint:gosec // read, then judged below
		CipherSuites: allSuites()}, timeout)
	if err != nil {
		return TLSInfo{}, nil, fmt.Errorf("%s: no TLS handshake: %w", target, err)
	}
	if len(state.PeerCertificates) == 0 {
		return TLSInfo{}, nil, fmt.Errorf("%s: the server sent no certificate", target)
	}
	leaf := state.PeerCertificates[0]
	info := TLSInfo{Target: target, Version: tls.VersionName(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite),
		Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), DNSNames: leaf.DNSNames, NotAfter: leaf.NotAfter}
	var findings []iac.Finding
	add := func(id, title, detail string) { findings = append(findings, finding(id, target, title, detail)) }

	// Expiry.
	left := leaf.NotAfter.Sub(now)
	switch {
	case left <= 0:
		add("DG-TLS-001", fmt.Sprintf("%s: the certificate expired on %s", target, leaf.NotAfter.Format("2 January 2006")),
			"Clients refuse it or warn. Renew it, and automate renewal, for example with ACME (Let's Encrypt) or cert-manager.")
	case left < 14*24*time.Hour:
		add("DG-TLS-002", fmt.Sprintf("%s: the certificate expires on %s", target, leaf.NotAfter.Format("2 January 2006")),
			"Renew it now, and check that renewal is automated.")
	case left < 30*24*time.Hour:
		add("DG-TLS-003", fmt.Sprintf("%s: the certificate expires on %s", target, leaf.NotAfter.Format("2 January 2006")),
			"Renew it soon, and check that renewal is automated.")
	}

	// Trust and name.
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	verify := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}
	if _, err := leaf.Verify(verify); err == nil {
		info.Trusted = true
	} else {
		// An expired certificate is reported as such above.
		var invalid x509.CertificateInvalidError
		if !(errors.As(err, &invalid) && invalid.Reason == x509.Expired) {
			add("DG-TLS-004", fmt.Sprintf("%s: the certificate isn't trusted (issued by %s)", target, leaf.Issuer.CommonName),
				"Browsers and clients that check certificates refuse it, and people learn to click through warnings. Use a certificate from a public authority, or your organisation's CA installed on every client.")
		}
	}
	if serverName != "" {
		if err := leaf.VerifyHostname(serverName); err != nil {
			add("DG-TLS-005", fmt.Sprintf("%s: the certificate isn't for %s", target, serverName),
				"Clients refuse it or warn. Use a certificate that names this host (in its subject alternative names).")
		}
	}

	// Key and signature.
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			add("DG-TLS-008", fmt.Sprintf("%s: the certificate's RSA key is %d bits", target, key.N.BitLen()),
				"Use a key of at least 2048 bits, or an ECDSA P-256 key.")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			add("DG-TLS-008", fmt.Sprintf("%s: the certificate's ECDSA key is %d bits", target, key.Curve.Params().BitSize),
				"Use a P-256 key or larger.")
		}
	}
	if leaf.SignatureAlgorithm == x509.SHA1WithRSA || leaf.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		add("DG-TLS-009", target+": the certificate is signed with SHA-1",
			"SHA-1 signatures can be forged. Get a certificate signed with SHA-256.")
	}

	// Protocol versions: each tried alone.
	versions := []struct {
		id   uint16
		name string
	}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"}}
	var old []string
	for _, v := range versions {
		config := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: v.id, MaxVersion: v.id, CipherSuites: allSuites()} //nolint:gosec // probing versions
		if _, err := handshake(ctx, target, serverName, config, timeout); err == nil {
			info.Protocols = append(info.Protocols, v.name)
			if v.id < tls.VersionTLS12 {
				old = append(old, v.name)
			}
		}
	}
	if len(old) > 0 {
		add("DG-TLS-006", fmt.Sprintf("%s: accepts %s", target, strings.Join(old, " and ")),
			"TLS 1.0 and 1.1 have known weaknesses and are retired (RFC 8996). Accept TLS 1.2 and 1.3 only.")
	}
	if len(info.Protocols) > 0 && !containsString(info.Protocols, "TLS 1.3") {
		add("DG-TLS-010", target+": doesn't offer TLS 1.3",
			"TLS 1.3 is faster and removes old options. Turn it on in the server or proxy.")
	}

	// Weak cipher suites, offered alone, up to TLS 1.2: broken ones (3DES,
	// RC4), and ones without forward secrecy (RSA key exchange).
	var weak, static []string
	for _, suite := range tls.InsecureCipherSuites() {
		broken := strings.Contains(suite.Name, "3DES") || strings.Contains(suite.Name, "RC4")
		noForwardSecrecy := strings.HasPrefix(suite.Name, "TLS_RSA_")
		if !broken && !noForwardSecrecy {
			continue
		}
		config := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, //nolint:gosec // probing ciphers
			CipherSuites: []uint16{suite.ID}}
		if _, err := handshake(ctx, target, serverName, config, timeout); err == nil {
			if broken {
				weak = append(weak, suite.Name)
			} else {
				static = append(static, suite.Name)
			}
		}
	}
	if len(weak) > 0 {
		add("DG-TLS-007", fmt.Sprintf("%s: accepts weak cipher suites: %s", target, strings.Join(weak, ", ")),
			"3DES and RC4 can be broken. Allow only AEAD suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy (ECDHE).")
	}
	if len(static) > 0 {
		add("DG-TLS-011", fmt.Sprintf("%s: accepts %d cipher suites without forward secrecy (RSA key exchange)", target, len(static)),
			"With RSA key exchange, anyone who later gets the server's key can decrypt recorded traffic. Prefer ECDHE suites, and drop TLS_RSA_* where old clients allow.")
	}
	return info, findings, nil
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
