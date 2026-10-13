package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// APITokenPrefix starts every API token, so secret scanners can find them.
const APITokenPrefix = "dgt_"

// MaxAPITokenLifetime is the longest an API token lasts; tokens can also
// last until revoked.
const MaxAPITokenLifetime = 365 * 24 * time.Hour

// APIToken lets a script or another tool use the API as an account, with a
// role up to the account's own. Only a hash of the token is stored.
type APIToken struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	LastUsedAt   string `json:"last_used_at"`
	LastUsedFrom string `json:"last_used_from"`
	RevokedAt    string `json:"revoked_at"`
	// Status is active, expired or revoked.
	Status string `json:"status"`
}

const apiTokenColumns = `t.id, t.user_id, u.username, t.name, t.role, t.created_at, t.expires_at, t.last_used_at, t.last_used_from, t.revoked_at`

func scanAPIToken(row rowScanner) (APIToken, error) {
	var token APIToken
	if err := row.Scan(&token.ID, &token.UserID, &token.Username, &token.Name, &token.Role, &token.CreatedAt, &token.ExpiresAt,
		&token.LastUsedAt, &token.LastUsedFrom, &token.RevokedAt); err != nil {
		return APIToken{}, err
	}
	switch {
	case token.RevokedAt != "":
		token.Status = "revoked"
	case token.ExpiresAt != "" && token.ExpiresAt <= nowText():
		token.Status = "expired"
	default:
		token.Status = "active"
	}
	return token, nil
}

// CreateAPIToken makes a token for user, named name, with role (at most the
// user's), lasting lifetime or, when zero, until revoked. The token itself is
// returned once.
func CreateAPIToken(user User, name, role string, lifetime time.Duration) (APIToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 || strings.ContainsFunc(name, unicode.IsControl) {
		return APIToken{}, "", errors.New("give the token a name of up to 80 characters, such as the script that uses it")
	}
	if !ValidRole(role) {
		return APIToken{}, "", ErrUnknownRole
	}
	if !RoleAllows(user.Role, role) {
		return APIToken{}, "", fmt.Errorf("a token can't have more than your own role, %s", user.Role)
	}
	if lifetime < 0 || lifetime > MaxAPITokenLifetime {
		return APIToken{}, "", errors.New("a token lasts up to 365 days, or until revoked")
	}
	db, err := database()
	if err != nil {
		return APIToken{}, "", err
	}
	secret, err := NewSecret()
	if err != nil {
		return APIToken{}, "", err
	}
	id, err := newID()
	if err != nil {
		return APIToken{}, "", err
	}
	token := APIPrefixed(secret)
	now := time.Now().UTC()
	expires := ""
	if lifetime > 0 {
		expires = now.Add(lifetime).Format(time.RFC3339)
	}
	if _, err := db.Exec(`INSERT INTO api_tokens (id, user_id, name, token_hash, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, user.ID, name, HashSecret(token), role, now.Format(time.RFC3339), expires); err != nil {
		return APIToken{}, "", err
	}
	created, err := GetAPIToken(id)
	return created, token, err
}

// APIPrefixed is a token as handed out: the prefix and the secret.
func APIPrefixed(secret string) string { return APITokenPrefix + secret }

var ErrUnknownAPIToken = errors.New("unknown API token")

func GetAPIToken(id string) (APIToken, error) {
	db, err := database()
	if err != nil {
		return APIToken{}, err
	}
	token, err := scanAPIToken(db.QueryRow("SELECT "+apiTokenColumns+" FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrUnknownAPIToken
	}
	return token, err
}

// APITokens lists a user's tokens, or everyone's when userID is empty,
// newest first. Revoked and expired tokens stay listed for 30 days.
func APITokens(userID string) ([]APIToken, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`DELETE FROM api_tokens WHERE (revoked_at != '' AND revoked_at < ?) OR (expires_at != '' AND expires_at < ?)`, cutoff, cutoff); err != nil {
		return nil, err
	}
	query, arguments := "SELECT "+apiTokenColumns+" FROM api_tokens t JOIN users u ON u.id = t.user_id", []any{}
	if userID != "" {
		query += " WHERE t.user_id = ?"
		arguments = append(arguments, userID)
	}
	rows, err := db.Query(query+" ORDER BY t.created_at DESC, t.rowid DESC", arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := make([]APIToken, 0)
	for rows.Next() {
		token, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// RevokeAPIToken stops a token working at once.
func RevokeAPIToken(id string) (APIToken, error) {
	db, err := database()
	if err != nil {
		return APIToken{}, err
	}
	if _, err := db.Exec("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = ''", nowText(), id); err != nil {
		return APIToken{}, err
	}
	return GetAPIToken(id)
}

// ErrBadAPIToken covers every token that can't be used: unknown, revoked,
// expired, or belonging to a disabled account.
var ErrBadAPIToken = errors.New("the API token is not valid: it may be revoked or expired")

// AuthenticateAPIToken returns the account a token acts as, with its role
// lowered to the token's when that is less, and records the use.
func AuthenticateAPIToken(token, remote string) (User, APIToken, error) {
	if !strings.HasPrefix(token, APITokenPrefix) {
		return User{}, APIToken{}, ErrBadAPIToken
	}
	db, err := database()
	if err != nil {
		return User{}, APIToken{}, err
	}
	found, err := scanAPIToken(db.QueryRow("SELECT "+apiTokenColumns+" FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?", HashSecret(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, APIToken{}, ErrBadAPIToken
	}
	if err != nil {
		return User{}, APIToken{}, err
	}
	if found.Status != "active" {
		return User{}, APIToken{}, ErrBadAPIToken
	}
	user, err := GetUser(found.UserID)
	if err != nil || user.Disabled {
		return User{}, APIToken{}, ErrBadAPIToken
	}
	// An account that lost a role takes its tokens down with it.
	if !RoleAllows(user.Role, found.Role) {
		found.Role = user.Role
	}
	user.Role = found.Role
	if seen, err := time.Parse(time.RFC3339, found.LastUsedAt); err != nil || time.Since(seen) > sessionTouchInterval || found.LastUsedFrom != remote {
		_, _ = db.Exec("UPDATE api_tokens SET last_used_at = ?, last_used_from = ? WHERE id = ?", nowText(), remote, found.ID)
	}
	return user, found, nil
}
