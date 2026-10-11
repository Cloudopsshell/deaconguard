package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// User is a dashboard account. Every account is an administrator.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	// MFAEnabled reports two-step sign-in with an authenticator app.
	MFAEnabled bool `json:"mfa_enabled"`
	// RecoveryCodesLeft counts the unused recovery codes.
	RecoveryCodesLeft int `json:"recovery_codes_left"`
	// MustChangePassword is set by a temporary password from an admin.
	MustChangePassword bool   `json:"must_change_password"`
	Disabled           bool   `json:"disabled"`
	LastLoginAt        string `json:"last_login_at"`
}

const (
	// passwordIterations follows OWASP's PBKDF2-HMAC-SHA256 recommendation.
	passwordIterations = 600_000
	MinPasswordLength  = 12
	// SessionLifetime is how long a sign-in lasts.
	SessionLifetime = 12 * time.Hour
)

var (
	ErrUserExists         = errors.New("a user with that name already exists")
	ErrInvalidCredentials = errors.New("incorrect username or password")
	ErrNoSession          = errors.New("not signed in")
	ErrAccountDisabled    = errors.New("this account is disabled; ask an administrator to turn it back on")
	ErrUnknownUser        = errors.New("unknown account")
	// ErrLastAccount keeps at least one account that can sign in.
	ErrLastAccount = errors.New("this is the only account that can sign in; add or turn on another account first")
)

// dummyHash is compared against when the username is unknown, so a failed
// sign-in takes as long whether or not the account exists.
var dummyHash = sync.OnceValue(func() string {
	return hashPasswordWith([]byte("deaconguard-no-such-user"), make([]byte, 16), passwordIterations)
})

func ValidateUsername(username string) error {
	if len(username) < 1 || len(username) > 64 {
		return errors.New("the username must be 1 to 64 characters")
	}
	for _, r := range username {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-@", r)) {
			return errors.New("the username may contain letters, digits, and . _ - @ only")
		}
	}
	return nil
}

func ValidatePassword(password []byte) error {
	if len([]rune(string(password))) < MinPasswordLength {
		return fmt.Errorf("the password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > 1024 {
		return errors.New("the password must be at most 1024 bytes")
	}
	return nil
}

func hashPassword(password []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashPasswordWith(password, salt, passwordIterations), nil
}

func hashPasswordWith(password, salt []byte, iterations int) string {
	key, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, 32)
	if err != nil {
		panic(err)
	}
	encode := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iterations, encode(salt), encode(key))
}

func checkPassword(encoded string, password []byte) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashPasswordWith(password, salt, iterations)), []byte(encoded)) == 1
}

// NewSecret returns a random 256-bit secret, base64url-encoded.
func NewSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// HashSecret is how tokens, sessions, and agent credentials are stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// AuditEntry is one recorded action.
type AuditEntry struct {
	ID     int64  `json:"id"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	Remote string `json:"remote"`
}

// keepAuditEntries bounds the audit log; the oldest entries are dropped.
const keepAuditEntries = 10_000

// Audit records an action. It never fails the action it records.
func Audit(actor, action, target, detail, remote string) {
	db, err := database()
	if err != nil {
		return
	}
	result, err := db.Exec("INSERT INTO audit_log (at, actor, action, target, detail, remote) VALUES (?, ?, ?, ?, ?, ?)",
		nowText(), actor, action, target, detail, remote)
	if err != nil {
		return
	}
	if id, err := result.LastInsertId(); err == nil && id%100 == 0 {
		db.Exec("DELETE FROM audit_log WHERE id <= ?", id-keepAuditEntries)
	}
}

// AuditLog returns the newest entries first.
func AuditLog(limit int) ([]AuditEntry, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := db.Query("SELECT id, at, actor, action, target, detail, remote FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.At, &entry.Actor, &entry.Action, &entry.Target, &entry.Detail, &entry.Remote); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
