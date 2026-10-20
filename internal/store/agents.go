package store

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// EnrollmentTokenLifetime is how long a new one-time enrollment token stays
// usable.
const EnrollmentTokenLifetime = 24 * time.Hour

// Reusable tokens last 30 days unless their creator picks from 1 to 365.
const (
	ReusableTokenLifetime    = 30 * 24 * time.Hour
	MaxReusableTokenLifetime = 365 * 24 * time.Hour
)

// EnrollmentToken is a token an agent uses to enroll. A one-time token
// enrolls one machine; a reusable one enrolls any number until it expires or
// is revoked, for machines that come and go, such as Kubernetes nodes. Only
// a hash of its secret is stored, so the token itself is shown once, when it
// is created.
type EnrollmentToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Reusable  bool   `json:"reusable"`
	Uses      int    `json:"uses"`
	ServerURL string `json:"server_url"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	// UsedAt is when a one-time token enrolled its machine, or when a
	// reusable one last enrolled one.
	UsedAt *string `json:"used_at"`
	// HostID is the machine a one-time token enrolled.
	HostID    *string `json:"host_id"`
	RevokedAt *string `json:"revoked_at"`
	// Status is active, used, expired, or revoked.
	Status string `json:"status"`
}

var ErrInvalidEnrollmentToken = errors.New("the enrollment token is invalid, expired, revoked, or already used")

// TokenOptions makes a reusable token. The zero value makes a one-time token
// that lasts EnrollmentTokenLifetime.
type TokenOptions struct {
	Reusable bool
	// Lifetime is how long a reusable token lasts: ReusableTokenLifetime
	// when zero, at most MaxReusableTokenLifetime.
	Lifetime time.Duration
	// Name says what a reusable token is for, such as a cluster's name.
	Name string
}

// CreateEnrollmentToken stores a new token and returns it with its secret.
func CreateEnrollmentToken(serverURL, createdBy string, options TokenOptions) (EnrollmentToken, string, error) {
	lifetime := EnrollmentTokenLifetime
	if options.Reusable {
		lifetime = options.Lifetime
		if lifetime == 0 {
			lifetime = ReusableTokenLifetime
		}
		if lifetime < time.Hour || lifetime > MaxReusableTokenLifetime {
			return EnrollmentToken{}, "", errors.New("a reusable token lasts from 1 to 365 days")
		}
	} else if options.Lifetime != 0 || options.Name != "" {
		return EnrollmentToken{}, "", errors.New("only reusable tokens take a lifetime and a name")
	}
	name := strings.TrimSpace(options.Name)
	if len(name) > 80 || strings.ContainsFunc(name, unicode.IsControl) {
		return EnrollmentToken{}, "", errors.New("a token's name is at most 80 characters, with no control characters")
	}
	db, err := database()
	if err != nil {
		return EnrollmentToken{}, "", err
	}
	secret, err := NewSecret()
	if err != nil {
		return EnrollmentToken{}, "", err
	}
	id, err := newID()
	if err != nil {
		return EnrollmentToken{}, "", err
	}
	now := time.Now().UTC()
	token := EnrollmentToken{
		ID: id, Name: name, Reusable: options.Reusable, ServerURL: serverURL, CreatedBy: createdBy, Status: "active",
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(lifetime).Format(time.RFC3339),
	}
	if _, err := db.Exec(`INSERT INTO enrollment_tokens (id, secret_hash, server_url, created_by, created_at, expires_at, reusable, name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, token.ID, HashSecret(secret), serverURL, createdBy, token.CreatedAt, token.ExpiresAt,
		token.Reusable, token.Name); err != nil {
		return EnrollmentToken{}, "", err
	}
	return token, secret, nil
}

// Describe says what kind of token this is, for the audit log.
func (token EnrollmentToken) Describe() string {
	kind := "one-time"
	if token.Reusable {
		kind = "reusable"
		if token.Name != "" {
			kind += " (" + token.Name + ")"
		}
	}
	return kind + ", for " + token.ServerURL + ", expires " + token.ExpiresAt
}

const tokenColumns = "id, server_url, created_by, created_at, expires_at, used_at, host_id, revoked_at, reusable, uses, name"

func scanToken(row rowScanner) (EnrollmentToken, error) {
	var token EnrollmentToken
	var usedAt, hostID, revokedAt sql.NullString
	if err := row.Scan(&token.ID, &token.ServerURL, &token.CreatedBy, &token.CreatedAt, &token.ExpiresAt,
		&usedAt, &hostID, &revokedAt, &token.Reusable, &token.Uses, &token.Name); err != nil {
		return EnrollmentToken{}, err
	}
	optional := func(value sql.NullString) *string {
		if !value.Valid {
			return nil
		}
		return &value.String
	}
	token.UsedAt, token.HostID, token.RevokedAt = optional(usedAt), optional(hostID), optional(revokedAt)
	switch {
	case token.RevokedAt != nil:
		token.Status = "revoked"
	case token.UsedAt != nil && !token.Reusable:
		token.Status = "used"
	case token.ExpiresAt <= nowText():
		token.Status = "expired"
	default:
		token.Status = "active"
	}
	return token, nil
}

// ListEnrollmentTokens returns tokens from the last 30 days, and reusable
// ones until 30 days after they expire, newest first.
func ListEnrollmentTokens() ([]EnrollmentToken, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	since := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec("DELETE FROM enrollment_tokens WHERE created_at < ? AND (reusable = 0 OR expires_at < ?)", since, since); err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + tokenColumns + " FROM enrollment_tokens ORDER BY created_at DESC, rowid DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := make([]EnrollmentToken, 0)
	for rows.Next() {
		token, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// RevokeEnrollmentToken stops a token from enrolling more machines. Machines
// it already enrolled stay enrolled.
func RevokeEnrollmentToken(id string) (EnrollmentToken, error) {
	db, err := database()
	if err != nil {
		return EnrollmentToken{}, err
	}
	if _, err := db.Exec("UPDATE enrollment_tokens SET revoked_at = ? WHERE id = ? AND (reusable = 1 OR used_at IS NULL) AND revoked_at IS NULL",
		nowText(), id); err != nil {
		return EnrollmentToken{}, err
	}
	token, err := scanToken(db.QueryRow("SELECT "+tokenColumns+" FROM enrollment_tokens WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentToken{}, fmt.Errorf("unknown enrollment token")
	}
	return token, err
}

// Agent describes an enrolled agent host.
type Agent struct {
	EnrolledAt string `json:"enrolled_at"`
	LastSeenAt string `json:"last_seen_at"`
	Version    string `json:"version"`
	OS         string `json:"os"`
	Remote     string `json:"remote"`
	// Port is the server port the agent last connected to, so admins can
	// see when every agent uses the agent port.
	Port string `json:"port"`
}

// AgentEnrollment is what an agent reports about itself when it enrolls.
type AgentEnrollment struct {
	// Kind is KindCluster for a cluster agent; empty is a machine.
	Kind     string
	Hostname string
	Username string
	Version  string
	OS       string
	Remote   string
}

// EnrollAgent spends a one-time token, or counts a use of a reusable one,
// and registers a new agent host. It returns the
// host and the credential the agent authenticates with from then on.
func EnrollAgent(secret string, enrollment AgentEnrollment) (Host, string, error) {
	db, err := database()
	if err != nil {
		return Host{}, "", err
	}
	credential, err := NewSecret()
	if err != nil {
		return Host{}, "", err
	}
	id, err := newID()
	if err != nil {
		return Host{}, "", err
	}
	tx, err := db.Begin()
	if err != nil {
		return Host{}, "", err
	}
	defer tx.Rollback()
	now := nowText()
	result, err := tx.Exec(`UPDATE enrollment_tokens SET used_at = ?, uses = uses + 1,
		host_id = CASE WHEN reusable = 1 THEN NULL ELSE ? END
		WHERE secret_hash = ? AND (reusable = 1 OR used_at IS NULL) AND revoked_at IS NULL AND expires_at > ?`,
		now, id, HashSecret(secret), now)
	if err != nil {
		return Host{}, "", err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Host{}, "", ErrInvalidEnrollmentToken
	}
	// Agents run the deeper checks as root or through passwordless sudo.
	kind := KindMachine
	if enrollment.Kind == KindCluster {
		kind = KindCluster
	} else if strings.HasPrefix(enrollment.OS, "macOS") {
		kind = KindMac
	}
	host := Host{ID: id, Address: enrollment.Hostname, Username: enrollment.Username, Transport: TransportAgent, AllowSudo: true, Kind: kind}
	if _, err := tx.Exec(`INSERT INTO hosts (id, address, username, transport, allow_sudo, kind, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)`,
		host.ID, host.Address, host.Username, host.Transport, host.Kind, now); err != nil {
		return Host{}, "", err
	}
	if _, err := tx.Exec(`INSERT INTO agents (host_id, credential_hash, enrolled_at, last_seen_at, version, os, remote)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, host.ID, HashSecret(credential), now, now,
		enrollment.Version, enrollment.OS, enrollment.Remote); err != nil {
		return Host{}, "", err
	}
	return host, credential, tx.Commit()
}

var ErrUnknownAgent = errors.New("this agent is not enrolled with the server; it may have been removed")

// AuthenticateAgent checks an agent's credential and records that it was seen.
func AuthenticateAgent(hostID, credential, version, remote, port string) (Host, error) {
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	var stored string
	err = db.QueryRow("SELECT credential_hash FROM agents WHERE host_id = ?", hostID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		HashSecret(credential)
		return Host{}, ErrUnknownAgent
	}
	if err != nil {
		return Host{}, err
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(HashSecret(credential))) != 1 {
		return Host{}, ErrUnknownAgent
	}
	if _, err := db.Exec("UPDATE agents SET last_seen_at = ?, version = ?, remote = ?, port = ? WHERE host_id = ?",
		nowText(), version, remote, port, hostID); err != nil {
		return Host{}, err
	}
	return GetHost(hostID)
}

// UpdateAgentHost records what an agent reports about its machine on each check-in.
func UpdateAgentHost(hostID, hostname, username, os string) error {
	db, err := database()
	if err != nil {
		return err
	}
	if _, err := db.Exec("UPDATE hosts SET address = ?, username = ? WHERE id = ? AND transport = ?",
		hostname, username, hostID, TransportAgent); err != nil {
		return err
	}
	_, err = db.Exec("UPDATE agents SET os = ? WHERE host_id = ?", os, hostID)
	return err
}

// Agents returns every enrolled agent keyed by host ID.
func Agents() (map[string]Agent, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT host_id, enrolled_at, last_seen_at, version, os, remote, port FROM agents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := make(map[string]Agent)
	for rows.Next() {
		var hostID string
		var agent Agent
		if err := rows.Scan(&hostID, &agent.EnrolledAt, &agent.LastSeenAt, &agent.Version, &agent.OS, &agent.Remote, &agent.Port); err != nil {
			return nil, err
		}
		agents[hostID] = agent
	}
	return agents, rows.Err()
}

// ValidHostname limits what an agent may call itself.
func ValidHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_')
	}) < 0
}
