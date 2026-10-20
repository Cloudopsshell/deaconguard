package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"deaconguard/internal/totp"
)

const (
	// PendingSessionLifetime is how long the second sign-in step may take.
	PendingSessionLifetime = 5 * time.Minute
	// RecoveryCodeCount is how many recovery codes MFA setup creates.
	RecoveryCodeCount = 10
	// sessionTouchInterval limits how often a session's last use is saved.
	sessionTouchInterval = time.Minute
)

// Session stages.
const (
	// StageFull is a complete sign-in.
	StageFull = "full"
	// StageMFA has the right password and waits for the second step.
	StageMFA = "mfa"
)

var (
	ErrWrongCode      = errors.New("that code is not right; check the time on your phone and try again")
	ErrNoPendingSetup = errors.New("start the authenticator setup again")
	ErrMFARequired    = errors.New("two-step sign-in is required for every account, so it cannot be turned off")
	ErrWrongPassword  = errors.New("the current password is not right")
)

// Session is one sign-in, as its owner sees it.
type Session struct {
	ID         string `json:"id"`
	UserID     string `json:"-"`
	Stage      string `json:"-"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	LastSeenAt string `json:"last_seen_at"`
	Remote     string `json:"remote"`
	UserAgent  string `json:"user_agent"`
	// Current marks the session that asked.
	Current bool `json:"current"`
}

const userColumns = `u.id, u.username, u.created_at, u.totp_secret != '', u.must_change_password, u.disabled, u.last_login_at,
	(SELECT COUNT(*) FROM recovery_codes r WHERE r.user_id = u.id AND r.used_at = ''), u.role, u.appearance,
	(SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id), u.oidc_subject != ''`

func scanUser(row rowScanner) (User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.MFAEnabled, &user.MustChangePassword, &user.Disabled,
		&user.LastLoginAt, &user.RecoveryCodesLeft, &user.Role, &user.Appearance, &user.Passkeys, &user.SSO)
	return user, err
}

// Roles, from the most to the least access. Admins manage accounts, enroll
// machines and remove hosts; operators run scans and schedules; viewers see
// results only.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// ValidRole reports whether role is one of the roles.
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleViewer
}

// RoleAllows reports whether an account with role may do what needs at least
// the role needed.
func RoleAllows(role, needed string) bool {
	rank := map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}
	return rank[role] >= rank[needed] && rank[needed] > 0
}

// AddUser creates a dashboard account with role. temporary makes the
// password one that has to be changed at the first sign-in.
func AddUser(username string, password []byte, role string, temporary bool) (User, error) {
	if !ValidRole(role) {
		return User{}, ErrUnknownRole
	}
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
	if _, err := db.Exec("INSERT INTO users (id, username, password_hash, created_at, must_change_password, role) VALUES (?, ?, ?, ?, ?, ?)",
		id, username, hash, nowText(), temporary, role); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrUserExists
		}
		return User{}, err
	}
	return GetUser(id)
}

// GetUser returns one account.
func GetUser(id string) (User, error) {
	db, err := database()
	if err != nil {
		return User{}, err
	}
	user, err := scanUser(db.QueryRow("SELECT "+userColumns+" FROM users u WHERE u.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUnknownUser
	}
	return user, err
}

// UserByName returns the account with a username.
func UserByName(username string) (User, error) {
	db, err := database()
	if err != nil {
		return User{}, err
	}
	user, err := scanUser(db.QueryRow("SELECT "+userColumns+" FROM users u WHERE u.username = ?", username))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("unknown user: %s", username)
	}
	return user, err
}

// ListUsers lists every account, oldest first.
func ListUsers() ([]User, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + userColumns + " FROM users u ORDER BY u.created_at, u.rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// Authenticate checks a username and password. It takes as long for an
// unknown username as for a known one.
func Authenticate(username string, password []byte) (User, error) {
	db, err := database()
	if err != nil {
		return User{}, err
	}
	var id, hash string
	err = db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&id, &hash)
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
	user, err := GetUser(id)
	if err != nil {
		return User{}, err
	}
	if user.Disabled {
		return User{}, ErrAccountDisabled
	}
	return user, nil
}

// MarkSignedIn records a completed sign-in.
func MarkSignedIn(userID string) {
	if db, err := database(); err == nil {
		db.Exec("UPDATE users SET last_login_at = ? WHERE id = ?", nowText(), userID)
	}
}

// CreateSession starts a session at stage and returns its token for the
// cookie. A pending second step lasts minutes; a full sign-in, hours.
func CreateSession(userID, stage, remote, userAgent string) (string, Session, error) {
	db, err := database()
	if err != nil {
		return "", Session{}, err
	}
	token, err := NewSecret()
	if err != nil {
		return "", Session{}, err
	}
	id, err := newID()
	if err != nil {
		return "", Session{}, err
	}
	now := time.Now().UTC()
	lifetime := SessionLifetime
	if stage != StageFull {
		lifetime = PendingSessionLifetime
	}
	session := Session{ID: id[:16], UserID: userID, Stage: stage, CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(lifetime).Format(time.RFC3339), LastSeenAt: now.Format(time.RFC3339),
		Remote: limitString(remote, 64), UserAgent: limitString(userAgent, 256)}
	if _, err := db.Exec("DELETE FROM sessions WHERE expires_at < ?", now.Format(time.RFC3339)); err != nil {
		return "", Session{}, err
	}
	if _, err := db.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at, id, stage, remote, user_agent, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, HashSecret(token), userID, session.CreatedAt, session.ExpiresAt, session.ID, stage,
		session.Remote, session.UserAgent, session.LastSeenAt); err != nil {
		return "", Session{}, err
	}
	return token, session, nil
}

// SessionUser returns the account and session a token belongs to, and
// records that the session was used.
func SessionUser(token string) (User, Session, error) {
	if token == "" {
		return User{}, Session{}, ErrNoSession
	}
	db, err := database()
	if err != nil {
		return User{}, Session{}, err
	}
	var session Session
	err = db.QueryRow(`SELECT id, user_id, stage, created_at, expires_at, last_seen_at, remote, user_agent FROM sessions
		WHERE token_hash = ? AND expires_at > ?`, HashSecret(token), nowText()).Scan(&session.ID, &session.UserID, &session.Stage,
		&session.CreatedAt, &session.ExpiresAt, &session.LastSeenAt, &session.Remote, &session.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, Session{}, ErrNoSession
	}
	if err != nil {
		return User{}, Session{}, err
	}
	user, err := GetUser(session.UserID)
	if errors.Is(err, ErrUnknownUser) {
		return User{}, Session{}, ErrNoSession
	}
	if err != nil {
		return User{}, Session{}, err
	}
	if user.Disabled {
		return User{}, Session{}, ErrNoSession
	}
	if seen, err := time.Parse(time.RFC3339, session.LastSeenAt); err != nil || time.Since(seen) > sessionTouchInterval {
		session.LastSeenAt = nowText()
		db.Exec("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", session.LastSeenAt, HashSecret(token))
	}
	return user, session, nil
}

// DeleteSession signs out the session with token.
func DeleteSession(token string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("DELETE FROM sessions WHERE token_hash = ?", HashSecret(token))
	return err
}

// UserSessions lists an account's signed-in sessions, newest first.
func UserSessions(userID, currentID string) ([]Session, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT id, created_at, expires_at, last_seen_at, remote, user_agent FROM sessions
		WHERE user_id = ? AND stage = ? AND expires_at > ? ORDER BY last_seen_at DESC`, userID, StageFull, nowText())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]Session, 0)
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.CreatedAt, &session.ExpiresAt, &session.LastSeenAt, &session.Remote, &session.UserAgent); err != nil {
			return nil, err
		}
		session.Current = session.ID == currentID
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// EndSessions signs an account out: one session by ID, or every session
// except keepID when id is "".
func EndSessions(userID, id, keepID string) (int64, error) {
	db, err := database()
	if err != nil {
		return 0, err
	}
	var result sql.Result
	if id != "" {
		result, err = db.Exec("DELETE FROM sessions WHERE user_id = ? AND id = ?", userID, id)
	} else {
		result, err = db.Exec("DELETE FROM sessions WHERE user_id = ? AND id != ?", userID, keepID)
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// StartTOTP creates a new authenticator secret for userID, kept pending until
// ConfirmTOTP proves the app has it. An existing setup keeps working until
// then.
func StartTOTP(userID string) (string, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return "", err
	}
	db, err := database()
	if err != nil {
		return "", err
	}
	if _, err := db.Exec("UPDATE users SET totp_pending = ? WHERE id = ?", secret, userID); err != nil {
		return "", err
	}
	return secret, nil
}

// ConfirmTOTP turns on the pending authenticator when code matches, and
// returns new recovery codes, which are shown once.
func ConfirmTOTP(userID, code string, now time.Time) ([]string, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	var pending string
	if err := db.QueryRow("SELECT totp_pending FROM users WHERE id = ?", userID).Scan(&pending); err != nil {
		return nil, err
	}
	if pending == "" {
		return nil, ErrNoPendingSetup
	}
	step, ok := totp.Verify(pending, code, now, 0)
	if !ok {
		return nil, ErrWrongCode
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE users SET totp_secret = totp_pending, totp_pending = '', totp_last_step = ? WHERE id = ?", step, userID); err != nil {
		return nil, err
	}
	codes, err := replaceRecoveryCodes(tx, userID)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// CheckTOTP verifies a code from userID's authenticator; each code works once.
func CheckTOTP(userID, code string, now time.Time) error {
	db, err := database()
	if err != nil {
		return err
	}
	var secret string
	var last int64
	if err := db.QueryRow("SELECT totp_secret, totp_last_step FROM users WHERE id = ?", userID).Scan(&secret, &last); err != nil {
		return err
	}
	if secret == "" {
		return ErrWrongCode
	}
	step, ok := totp.Verify(secret, code, now, last)
	if !ok {
		return ErrWrongCode
	}
	// Only one sign-in may use a step, even if two arrive together.
	result, err := db.Exec("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?", step, userID, step)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrWrongCode
	}
	return nil
}

// UseRecoveryCode signs in with one of userID's recovery codes, which then
// stops working.
func UseRecoveryCode(userID, code string) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at = ''",
		nowText(), userID, HashSecret(normalizeRecoveryCode(code)))
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrWrongCode
	}
	return nil
}

// NewRecoveryCodes replaces userID's recovery codes and returns the new ones.
func NewRecoveryCodes(userID string) ([]string, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	codes, err := replaceRecoveryCodes(tx, userID)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

var recoveryEncoding = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)

func replaceRecoveryCodes(tx *sql.Tx, userID string) ([]string, error) {
	if _, err := tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID); err != nil {
		return nil, err
	}
	codes := make([]string, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		random := make([]byte, 7)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		text := recoveryEncoding.EncodeToString(random)[:10]
		code := text[:5] + "-" + text[5:]
		if _, err := tx.Exec("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", userID, HashSecret(normalizeRecoveryCode(code))); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// normalizeRecoveryCode ignores case, spaces and dashes in a typed code.
func normalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(code)))
}

// RemoveMFA turns off userID's authenticator app and deletes its recovery
// codes; an admin's reset also removes its passkeys and signs the account
// out everywhere.
func RemoveMFA(userID string, signOut bool) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE users SET totp_secret = '', totp_pending = '', totp_last_step = 0 WHERE id = ?", userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrUnknownUser
	}
	if _, err := tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID); err != nil {
		return err
	}
	if signOut {
		if _, err := tx.Exec("DELETE FROM passkeys WHERE user_id = ?", userID); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CheckPassword reports whether password is userID's current password.
func CheckPassword(userID string, password []byte) error {
	db, err := database()
	if err != nil {
		return err
	}
	var hash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash); err != nil {
		return err
	}
	if !checkPassword(hash, password) {
		return ErrWrongPassword
	}
	return nil
}

// ChangePassword sets userID's own new password and signs out its other
// sessions. temporary makes it a password an admin chose, to be changed at
// the next sign-in, and signs out every session.
func ChangePassword(userID string, password []byte, keepSessionID string, temporary bool) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?", hash, temporary, userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrUnknownUser
	}
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id = ? AND id != ?", userID, keepSessionID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPassword changes a password from the server's command line and signs
// the account out everywhere.
func SetPassword(username string, password []byte) error {
	user, err := UserByName(username)
	if err != nil {
		return err
	}
	return ChangePassword(user.ID, password, "", false)
}

// activeAdmins counts administrators that can sign in.
func activeAdmins(tx *sql.Tx) (int, error) {
	var count int
	err := tx.QueryRow("SELECT COUNT(*) FROM users WHERE disabled = 0 AND role = ?", RoleAdmin).Scan(&count)
	return count, err
}

// keepsAnAdmin returns ErrLastAccount when user is the last administrator
// that can sign in, so taking it away would leave nobody to manage accounts.
func keepsAnAdmin(tx *sql.Tx, user User) error {
	if user.Disabled || user.Role != RoleAdmin {
		return nil
	}
	count, err := activeAdmins(tx)
	if err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastAccount
	}
	return nil
}

// SetRole changes an account's role and signs it out everywhere, so the new
// role applies at once. The last administrator that can sign in keeps its role.
func SetRole(userID, role string) error {
	if !ValidRole(role) {
		return ErrUnknownRole
	}
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	user, err := scanUser(tx.QueryRow("SELECT "+userColumns+" FROM users u WHERE u.id = ?", userID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownUser
	}
	if err != nil {
		return err
	}
	if user.Role == role {
		return nil
	}
	if err := keepsAnAdmin(tx, user); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetAppearance saves the dashboard mode and theme an account chose.
func SetAppearance(userID, appearance string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE users SET appearance = ? WHERE id = ?", limitString(appearance, 200), userID)
	return err
}

// SetDisabled turns an account off, signing it out everywhere, or back on.
// The last administrator that can sign in cannot be turned off.
func SetDisabled(userID string, disabled bool) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	user, err := scanUser(tx.QueryRow("SELECT "+userColumns+" FROM users u WHERE u.id = ?", userID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownUser
	}
	if err != nil {
		return err
	}
	if disabled && !user.Disabled {
		if err := keepsAnAdmin(tx, user); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("UPDATE users SET disabled = ? WHERE id = ?", disabled, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveUser deletes an account and its sessions. The last administrator
// that can sign in cannot be removed.
func RemoveUser(username string) error {
	user, err := UserByName(username)
	if err != nil {
		return err
	}
	return RemoveUserID(user.ID)
}

// RemoveUserID deletes an account by ID.
func RemoveUserID(userID string) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	user, err := scanUser(tx.QueryRow("SELECT "+userColumns+" FROM users u WHERE u.id = ?", userID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownUser
	} else if err != nil {
		return err
	}
	if err := keepsAnAdmin(tx, user); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
		return err
	}
	return tx.Commit()
}

// metaRequireMFA holds whether every account must use two-step sign-in.
const metaRequireMFA = "require_mfa"

// RequireMFA reports whether every account must use two-step sign-in.
func RequireMFA() (bool, error) {
	value, err := Meta(metaRequireMFA)
	return value == "1", err
}

// SetRequireMFA turns the requirement on or off.
func SetRequireMFA(required bool) error {
	value := "0"
	if required {
		value = "1"
	}
	return SetMeta(metaRequireMFA, value)
}

func limitString(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	if len(value) > limit {
		value = strings.ToValidUTF8(value[:limit], "")
	}
	return value
}
