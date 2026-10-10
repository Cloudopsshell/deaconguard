// Package agentapi is the protocol between a DeaconGuard server and its agents:
// the enrollment token format, how an agent trusts the server's certificate,
// and the JSON messages they exchange over HTTPS. The agent always connects to
// the server; the server never connects to an agent.
package agentapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"deaconguard/internal/scan"
	"deaconguard/internal/target"
)

// PathPrefix is where the server answers agents.
const PathPrefix = "/agent/v1/"

// tokenPrefix marks and versions an enrollment token.
const tokenPrefix = "deaconguard1."

// Token is what an enrollment token carries: where the server is, the
// fingerprint of its certificate's public key, and the one-time secret.
type Token struct {
	ServerURL string
	// Pin is the base64url SHA-256 of the server certificate's
	// SubjectPublicKeyInfo.
	Pin    string
	Secret string
}

// Encode returns the token as one copy-and-paste string.
func (t Token) Encode() string {
	encode := base64.RawURLEncoding.EncodeToString
	return tokenPrefix + encode([]byte(t.ServerURL)) + "." + t.Pin + "." + t.Secret
}

// ParseToken reads a token made by Encode.
func ParseToken(value string) (Token, error) {
	value = strings.TrimSpace(value)
	rest, found := strings.CutPrefix(value, tokenPrefix)
	parts := strings.Split(rest, ".")
	if !found || len(parts) != 3 {
		return Token{}, errors.New("this is not a DeaconGuard enrollment token; copy it again from the server's Agents page")
	}
	serverURL, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Token{}, errors.New("the enrollment token is damaged; copy it again")
	}
	token := Token{ServerURL: string(serverURL), Pin: parts[1], Secret: parts[2]}
	if err := ValidateServerURL(token.ServerURL); err != nil {
		return Token{}, err
	}
	for _, field := range []string{token.Pin, token.Secret} {
		if decoded, err := base64.RawURLEncoding.DecodeString(field); err != nil || len(decoded) != 32 {
			return Token{}, errors.New("the enrollment token is damaged; copy it again")
		}
	}
	return token, nil
}

// ValidateServerURL accepts an https:// URL with a host and nothing else.
func ValidateServerURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("the server address must look like https://deaconguard.example.com:8443, not %q", value)
	}
	return nil
}

// PublicKeyPin returns the pin of a certificate: the base64url SHA-256 of its
// SubjectPublicKeyInfo, which survives re-issuing a certificate for the same key.
func PublicKeyPin(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ClientTLS trusts the server whose certificate key matches pin. A server
// certificate that the system's certificate authorities trust for its name is
// also accepted, so a server that later switches to such a certificate keeps
// its agents.
func ClientTLS(serverName, pin string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		// Verification is done in VerifyConnection, which pins the key.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("the server sent no certificate")
			}
			leaf := state.PeerCertificates[0]
			if subtle.ConstantTimeCompare([]byte(PublicKeyPin(leaf)), []byte(pin)) == 1 {
				return nil
			}
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: intermediates}); err == nil {
				return nil
			}
			return errors.New("the server's certificate does not match the one this agent enrolled with; " +
				"if the server's certificate was replaced, enroll this agent again with a new token")
		},
	}
}

// EnrollRequest is sent with a token's secret to POST /agent/v1/enroll.
type EnrollRequest struct {
	Secret   string `json:"secret"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Version  string `json:"version"`
}

// EnrollResponse gives the agent its identity. Credential authenticates every
// later request as "Authorization: Bearer HOST_ID.CREDENTIAL".
type EnrollResponse struct {
	HostID     string `json:"host_id"`
	Credential string `json:"credential"`
}

// Job is a scan the server wants run, returned by GET /agent/v1/job.
type Job struct {
	ScanID    string   `json:"scan_id"`
	Checks    []string `json:"checks"`
	AllowSudo bool     `json:"allow_sudo"`
}

// JobWait is how long the server holds GET /agent/v1/job open when there is
// no scan to run; the agent asks again as soon as it returns.
const JobWait = 25 * time.Second

// Events carries live progress lines to POST /agent/v1/scans/{id}/events.
type Events struct {
	Events []scan.Event `json:"events"`
}

// Result finishes a scan at POST /agent/v1/scans/{id}/result. Inventory holds
// the collected packages when the scan included the package check.
type Result struct {
	Report    map[string]any    `json:"report,omitempty"`
	Inventory *target.Inventory `json:"inventory,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// MaxResultBytes bounds a result, which holds the whole package database.
const MaxResultBytes = 80 << 20

// PathYARARules serves the advanced antivirus scan's rules, gzip-compressed,
// with their version in HeaderRulesVersion. Agents fetch them for each
// advanced scan, so they need no internet access of their own.
const (
	PathYARARules      = "yara-rules"
	HeaderRulesVersion = "X-DeaconGuard-Rules-Version"
	// MaxYARARulesBytes bounds the compressed rules; the core package is about 2 MB.
	MaxYARARulesBytes = 32 << 20
)

// PathLogs receives the agent's own log lines, which the dashboard shows on
// the host's page. Agents send at most MaxLogLines at a time.
const (
	PathLogs    = "logs"
	MaxLogLines = 500
)

// LogLine is one line of the agent's log. Level is info, warning, or error.
type LogLine struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

// Logs carries log lines to POST /agent/v1/logs.
type Logs struct {
	Lines []LogLine `json:"lines"`
}

// Headers the agent sends with every request.
const (
	HeaderVersion  = "X-DeaconGuard-Agent-Version"
	HeaderHostname = "X-DeaconGuard-Agent-Hostname"
	HeaderUsername = "X-DeaconGuard-Agent-Username"
	HeaderOS       = "X-DeaconGuard-Agent-OS"
)

// SupportsYARA reports whether an agent of version runs the advanced
// antivirus scan, which arrived in 0.5.0. Builds without a release version,
// such as "dev", are assumed to.
func SupportsYARA(version string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d.", &major, &minor); err != nil {
		return version != ""
	}
	return major > 0 || minor >= 5
}

// ErrNeedsNewerAgent explains why an advanced scan was refused for an agent.
func ErrNeedsNewerAgent(address, version string) error {
	if version == "" {
		version = "an unknown version"
	}
	return fmt.Errorf("the advanced antivirus scan needs the DeaconGuard agent 0.5.0 or later on %s, which runs %s; "+
		"upgrade it there with: curl -fsSL https://get.deaconguard.io | sudo sh -", address, version)
}
