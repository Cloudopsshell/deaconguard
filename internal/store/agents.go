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
	// Hosts are the hosts the token enrolled that still exist (1.21.0 and
	// later; earlier enrollments where it is certain).
	Hosts []TokenHost `json:"hosts"`
}

// TokenHost is a host a token enrolled.
type TokenHost struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Kind    string `json:"kind"`
	// Disconnected is when the host was disconnected, if it was.
	Disconnected string `json:"disconnected,omitempty"`
}

var ErrInvalidEnrollmentToken = errors.New("the enrollment token is invalid, expired, revoked, or already used")

// tokenRejected says why a token can't enroll; it is an
// ErrInvalidEnrollmentToken.
type tokenRejected struct{ reason string }

func (err tokenRejected) Error() string { return err.reason }
func (err tokenRejected) Is(target error) bool {
	return target == ErrInvalidEnrollmentToken
}

// rejection explains why the token with this secret can't enroll a machine.
func rejection(tx *sql.Tx, secret string) error {
	token, err := scanToken(tx.QueryRow("SELECT "+tokenColumns+" FROM enrollment_tokens WHERE secret_hash = ?", HashSecret(secret)))
	if err != nil {
		return tokenRejected{"the enrollment token isn't known to this server: it was made by another server, or deleted. Create a new one on the Agents page"}
	}
	short := token.ID[:8]
	switch token.Status {
	case "revoked":
		return tokenRejected{fmt.Sprintf("the enrollment token %s was revoked on %s. Create a new one on the Agents page", short, readableTime(*token.RevokedAt))}
	case "used":
		return tokenRejected{fmt.Sprintf("the enrollment token %s is a one-time token, already used on %s to enroll another machine. Create a new one, or a reusable one for several machines", short, readableTime(*token.UsedAt))}
	case "expired":
		return tokenRejected{fmt.Sprintf("the enrollment token %s expired on %s. Create a new one on the Agents page", short, readableTime(token.ExpiresAt))}
	}
	return ErrInvalidEnrollmentToken
}

// readableTime turns a stored time into one people read, in UTC.
func readableTime(stored string) string {
	at, err := time.Parse(time.RFC3339, stored)
	if err != nil {
		return stored
	}
	return at.UTC().Format("2006-01-02 15:04 UTC")
}

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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hosts, err := tokenHosts(db, "")
	if err != nil {
		return nil, err
	}
	for index := range tokens {
		tokens[index].Hosts = hosts[tokens[index].ID]
		if tokens[index].Hosts == nil {
			tokens[index].Hosts = []TokenHost{}
		}
	}
	return tokens, nil
}

// tokenHosts lists the hosts each token enrolled, or only token's.
func tokenHosts(db *sql.DB, token string) (map[string][]TokenHost, error) {
	rows, err := db.Query(`SELECT agents.token_id, hosts.id, COALESCE(NULLIF(hosts.display_name, ''), hosts.address), hosts.kind, hosts.disconnected_at
		FROM agents JOIN hosts ON hosts.id = agents.host_id WHERE agents.token_id != '' AND (? = '' OR agents.token_id = ?)
		ORDER BY hosts.kind = 'cluster' DESC, 3`, token, token)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hosts := map[string][]TokenHost{}
	for rows.Next() {
		var tokenID string
		var host TokenHost
		if err := rows.Scan(&tokenID, &host.ID, &host.Address, &host.Kind, &host.Disconnected); err != nil {
			return nil, err
		}
		hosts[tokenID] = append(hosts[tokenID], host)
	}
	return hosts, rows.Err()
}

// GetEnrollmentToken returns a token with the hosts it enrolled.
func GetEnrollmentToken(id string) (EnrollmentToken, error) {
	db, err := database()
	if err != nil {
		return EnrollmentToken{}, err
	}
	token, err := scanToken(db.QueryRow("SELECT "+tokenColumns+" FROM enrollment_tokens WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentToken{}, fmt.Errorf("unknown enrollment token")
	}
	if err != nil {
		return EnrollmentToken{}, err
	}
	hosts, err := tokenHosts(db, id)
	token.Hosts = hosts[id]
	if token.Hosts == nil {
		token.Hosts = []TokenHost{}
	}
	return token, err
}

// RevokeEnrollmentToken stops a token from enrolling more machines. With
// disconnect, the machines it enrolled are disconnected too: their agents
// are refused from then on, told why, and their hosts say why on the
// dashboard; their scans stay. It returns the token and the hosts it
// disconnected.
func RevokeEnrollmentToken(id, by string, disconnect bool) (EnrollmentToken, []TokenHost, error) {
	db, err := database()
	if err != nil {
		return EnrollmentToken{}, nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return EnrollmentToken{}, nil, err
	}
	defer tx.Rollback()
	now := nowText()
	if _, err := tx.Exec("UPDATE enrollment_tokens SET revoked_at = ? WHERE id = ? AND (reusable = 1 OR used_at IS NULL) AND revoked_at IS NULL",
		now, id); err != nil {
		return EnrollmentToken{}, nil, err
	}
	var disconnected []TokenHost
	if disconnect {
		reason := fmt.Sprintf("its enrollment token %s was revoked, with the machines it enrolled", id[:min(8, len(id))])
		rows, err := tx.Query(`SELECT hosts.id, COALESCE(NULLIF(hosts.display_name, ''), hosts.address), hosts.kind FROM agents
			JOIN hosts ON hosts.id = agents.host_id WHERE agents.token_id = ? AND hosts.disconnected_at = ''`, id)
		if err != nil {
			return EnrollmentToken{}, nil, err
		}
		for rows.Next() {
			var host TokenHost
			if err := rows.Scan(&host.ID, &host.Address, &host.Kind); err != nil {
				rows.Close()
				return EnrollmentToken{}, nil, err
			}
			host.Disconnected = now
			disconnected = append(disconnected, host)
		}
		rows.Close()
		for _, host := range disconnected {
			if _, err := tx.Exec("UPDATE hosts SET disconnected_at = ?, disconnected_by = ?, disconnect_reason = ? WHERE id = ?",
				now, by, reason, host.ID); err != nil {
				return EnrollmentToken{}, nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentToken{}, nil, err
	}
	token, err := GetEnrollmentToken(id)
	return token, disconnected, err
}

// DeleteRevokedTokens removes every revoked token from the list, and says
// how many. The hosts they enrolled stay as they are.
func DeleteRevokedTokens() (int, error) {
	db, err := database()
	if err != nil {
		return 0, err
	}
	result, err := db.Exec("DELETE FROM enrollment_tokens WHERE revoked_at IS NOT NULL")
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	return int(removed), err
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
	// Name is the display name given at enrollment, if any.
	Name     string
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
	// Agents run the deeper checks as root or through passwordless sudo.
	kind := KindMachine
	if enrollment.Kind == KindCluster {
		kind = KindCluster
	} else if strings.HasPrefix(enrollment.OS, "macOS") {
		kind = KindMac
	}
	// A machine disconnected when its token was revoked takes its host back
	// when it enrolls again, with its scans: only an agent enrolled with a
	// valid token gets here.
	var reconnected string
	err = tx.QueryRow(`SELECT id FROM hosts WHERE transport = ? AND kind = ? AND address = ? AND disconnected_at != ''
		ORDER BY disconnected_at DESC LIMIT 1`, TransportAgent, kind, enrollment.Hostname).Scan(&reconnected)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Host{}, "", err
	}
	if reconnected != "" {
		id = reconnected
	}
	var tokenID string
	err = tx.QueryRow(`UPDATE enrollment_tokens SET used_at = ?, uses = uses + 1,
		host_id = CASE WHEN reusable = 1 THEN NULL ELSE ? END
		WHERE secret_hash = ? AND (reusable = 1 OR used_at IS NULL) AND revoked_at IS NULL AND expires_at > ?
		RETURNING id`, now, id, HashSecret(secret), now).Scan(&tokenID)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, "", rejection(tx, secret)
	}
	if err != nil {
		return Host{}, "", err
	}
	host := Host{ID: id, Address: enrollment.Hostname, Hostname: enrollment.Hostname, Name: enrollment.Name, Username: enrollment.Username,
		Transport: TransportAgent, AllowSudo: true, Kind: kind}
	if reconnected != "" {
		if host, err = scanHost(tx.QueryRow("SELECT "+hostColumns+" FROM hosts WHERE id = ?", id)); err != nil {
			return Host{}, "", err
		}
		if _, err := tx.Exec(`UPDATE hosts SET username = ?, disconnected_at = '', disconnected_by = '', disconnect_reason = '' WHERE id = ?`,
			enrollment.Username, id); err != nil {
			return Host{}, "", err
		}
		host.Disconnected, host.Username = nil, enrollment.Username
		if _, err := tx.Exec(`UPDATE agents SET credential_hash = ?, enrolled_at = ?, last_seen_at = ?, version = ?, os = ?, remote = ?, token_id = ?
			WHERE host_id = ?`, HashSecret(credential), now, now, enrollment.Version, enrollment.OS, enrollment.Remote, tokenID, id); err != nil {
			return Host{}, "", err
		}
		return host, credential, tx.Commit()
	}
	if host.Name != "" {
		host.Address = host.Name
	}
	if _, err := tx.Exec(`INSERT INTO hosts (id, address, display_name, username, transport, allow_sudo, kind, created_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		host.ID, host.Hostname, host.Name, host.Username, host.Transport, host.Kind, now); err != nil {
		return Host{}, "", err
	}
	if _, err := tx.Exec(`INSERT INTO agents (host_id, credential_hash, enrolled_at, last_seen_at, version, os, remote, token_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, host.ID, HashSecret(credential), now, now,
		enrollment.Version, enrollment.OS, enrollment.Remote, tokenID); err != nil {
		return Host{}, "", err
	}
	return host, credential, tx.Commit()
}

var ErrUnknownAgent = errors.New("this agent is not enrolled with the server; it may have been removed")

// AgentDisconnected is why an agent may no longer connect: its host was
// disconnected. It is an ErrUnknownAgent.
type AgentDisconnected struct{ Disconnection }

func (err AgentDisconnected) Error() string {
	message := "this agent was disconnected on " + readableTime(err.At)
	if err.By != "" {
		message += " by " + err.By
	}
	return message + ": " + err.Reason + ". To reconnect it, enroll it again with a new token; it keeps its host and its scans"
}

func (err AgentDisconnected) Is(target error) bool { return target == ErrUnknownAgent }

// AuthenticateAgent checks an agent's credential and records that it was seen.
func AuthenticateAgent(hostID, credential, version, remote, port string) (Host, error) {
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	var stored string
	var disconnected Disconnection
	err = db.QueryRow(`SELECT credential_hash, hosts.disconnected_at, hosts.disconnected_by, hosts.disconnect_reason
		FROM agents JOIN hosts ON hosts.id = agents.host_id WHERE host_id = ?`, hostID).Scan(&stored, &disconnected.At, &disconnected.By, &disconnected.Reason)
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
	// Only the agent itself learns why: its credential is checked first.
	if disconnected.At != "" {
		return Host{}, AgentDisconnected{disconnected}
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

// LinkClusterNodes records which hosts are the nodes of a cluster, from the
// node names its cluster agent reported: the agent hosts of machines with
// those names. When two machines share a name, the one enrolled with the
// cluster's token wins, then one already linked; otherwise neither is
// linked. Hosts no longer among its nodes are unlinked.
func LinkClusterNodes(clusterID string, nodeNames []string) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var clusterToken string
	if err := tx.QueryRow("SELECT token_id FROM agents WHERE host_id = ?", clusterID).Scan(&clusterToken); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec("UPDATE hosts SET cluster_id = '' WHERE cluster_id = ?", clusterID); err != nil {
		return err
	}
	for _, name := range nodeNames {
		rows, err := tx.Query(`SELECT hosts.id, COALESCE(agents.token_id, ''), hosts.cluster_id FROM hosts LEFT JOIN agents ON agents.host_id = hosts.id
			WHERE hosts.transport = ? AND hosts.kind = ? AND hosts.address = ?`, TransportAgent, KindMachine, name)
		if err != nil {
			return err
		}
		var candidates [][3]string
		for rows.Next() {
			var candidate [3]string
			if err := rows.Scan(&candidate[0], &candidate[1], &candidate[2]); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, candidate)
		}
		rows.Close()
		chosen := ""
		if len(candidates) == 1 {
			chosen = candidates[0][0]
		}
		for _, candidate := range candidates {
			if chosen == "" && clusterToken != "" && candidate[1] == clusterToken {
				chosen = candidate[0]
			}
		}
		if chosen == "" {
			continue
		}
		if _, err := tx.Exec("UPDATE hosts SET cluster_id = ? WHERE id = ?", clusterID, chosen); err != nil {
			return err
		}
	}
	return tx.Commit()
}
