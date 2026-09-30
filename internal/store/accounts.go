package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
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

// AddUser creates a dashboard account.
func AddUser(username string, password []byte) (User, error) {
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	db, err := database()
	if err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, err := newID()
	if err != nil {
		return User{}, err
	}
	user := User{ID: id, Username: username, CreatedAt: nowText()}
	if _, err := db.Exec("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
		user.ID, user.Username, hash, user.CreatedAt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrUserExists
		}
		return User{}, err
	}
	return user, nil
}

// SetPassword changes a user's password and signs out all their sessions.
func SetPassword(username string, password []byte) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	db, err := database()
	if err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	if err := tx.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("unknown user: %s", username)
	} else if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE users SET password_hash = ? WHERE id = ?", hash, id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id = ?", id); err != nil {
		return err
	}
	return tx.Commit()
}

func ListUsers() ([]User, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT id, username, created_at FROM users ORDER BY created_at, rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// RemoveUser deletes an account and its sessions.
func RemoveUser(username string) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return fmt.Errorf("unknown user: %s", username)
	}
	return nil
}

// Authenticate checks a username and password.
func Authenticate(username string, password []byte) (User, error) {
	db, err := database()
	if err != nil {
		return User{}, err
	}
	var user User
	var hash string
	err = db.QueryRow("SELECT id, username, created_at, password_hash FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		checkPassword(dummyHash(), password)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, err
	}
	if !checkPassword(hash, password) {
		return User{}, ErrInvalidCredentials
	}
	return user, nil
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

// CreateSession signs a user in and returns the session token for the cookie.
func CreateSession(userID string) (string, time.Time, error) {
	db, err := database()
	if err != nil {
		return "", time.Time{}, err
	}
	token, err := NewSecret()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(SessionLifetime)
	if _, err := db.Exec("DELETE FROM sessions WHERE expires_at < ?", now.Format(time.RFC3339)); err != nil {
		return "", time.Time{}, err
	}
	if _, err := db.Exec("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		HashSecret(token), userID, now.Format(time.RFC3339), expires.Format(time.RFC3339)); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// SessionUser returns the user a session token belongs to.
func SessionUser(token string) (User, error) {
	if token == "" {
		return User{}, ErrNoSession
	}
	db, err := database()
	if err != nil {
		return User{}, err
	}
	var user User
	err = db.QueryRow(`SELECT u.id, u.username, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, HashSecret(token), nowText()).Scan(&user.ID, &user.Username, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNoSession
	}
	return user, err
}

func DeleteSession(token string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM sessions WHERE token_hash = ?", HashSecret(token))
	return err
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
