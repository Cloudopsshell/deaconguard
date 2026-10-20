package store

import (
	"database/sql"
	"errors"
	"strings"
)

// Passkey is a WebAuthn credential that signs an account in. Only its public
// key is kept; the private key never leaves the person's device or password
// manager.
type Passkey struct {
	ID           string `json:"id"`
	UserID       string `json:"-"`
	CredentialID []byte `json:"-"`
	PublicKey    []byte `json:"-"`
	// Algorithm is the COSE algorithm: -7 (ES256), -8 (EdDSA) or -257 (RS256).
	Algorithm  int      `json:"-"`
	SignCount  uint32   `json:"-"`
	Name       string   `json:"name"`
	Transports []string `json:"transports,omitempty"`
	CreatedAt  string   `json:"created_at"`
	LastUsedAt string   `json:"last_used_at"`
}

// MaxPasskeys bounds an account's passkeys.
const MaxPasskeys = 20

var (
	ErrPasskeyExists   = errors.New("this passkey is already registered")
	ErrUnknownPasskey  = errors.New("this passkey isn't registered with DeaconGuard; sign in with your password, or add the passkey on My account")
	ErrTooManyPasskeys = errors.New("an account can have at most 20 passkeys; remove one first")
	ErrLastTwoStep     = errors.New("two-step sign-in is required for every account, and this is your only passkey with no authenticator app; set up the app or add another passkey first")
)

const passkeyColumns = "id, user_id, credential_id, public_key, algorithm, sign_count, name, transports, created_at, last_used_at"

func scanPasskey(row rowScanner) (Passkey, error) {
	var key Passkey
	var transports string
	var count int64
	err := row.Scan(&key.ID, &key.UserID, &key.CredentialID, &key.PublicKey, &key.Algorithm, &count, &key.Name, &transports,
		&key.CreatedAt, &key.LastUsedAt)
	key.SignCount = uint32(count)
	if transports != "" {
		key.Transports = strings.Split(transports, ",")
	}
	return key, err
}

// AddPasskey saves a passkey for key.UserID.
func AddPasskey(key Passkey) (Passkey, error) {
	db, err := database()
	if err != nil {
		return Passkey{}, err
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM passkeys WHERE user_id = ?", key.UserID).Scan(&count); err != nil {
		return Passkey{}, err
	}
	if count >= MaxPasskeys {
		return Passkey{}, ErrTooManyPasskeys
	}
	if key.ID, err = newID(); err != nil {
		return Passkey{}, err
	}
	key.Name = limitString(strings.TrimSpace(key.Name), 64)
	if key.Name == "" {
		key.Name = "Passkey"
	}
	key.CreatedAt = nowText()
	if _, err := db.Exec("INSERT INTO passkeys ("+passkeyColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '')",
		key.ID, key.UserID, key.CredentialID, key.PublicKey, key.Algorithm, int64(key.SignCount), key.Name,
		strings.Join(key.Transports, ","), key.CreatedAt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Passkey{}, ErrPasskeyExists
		}
		return Passkey{}, err
	}
	return key, nil
}

// Passkeys lists userID's passkeys, the oldest first.
func Passkeys(userID string) ([]Passkey, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT "+passkeyColumns+" FROM passkeys WHERE user_id = ? ORDER BY created_at, id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]Passkey, 0)
	for rows.Next() {
		key, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// PasskeyByCredential finds a passkey by its WebAuthn credential ID.
func PasskeyByCredential(credentialID []byte) (Passkey, error) {
	db, err := database()
	if err != nil {
		return Passkey{}, err
	}
	key, err := scanPasskey(db.QueryRow("SELECT "+passkeyColumns+" FROM passkeys WHERE credential_id = ?", credentialID))
	if errors.Is(err, sql.ErrNoRows) {
		return Passkey{}, ErrUnknownPasskey
	}
	return key, err
}

// UsedPasskey records a sign-in with a passkey and its new signature count.
func UsedPasskey(id string, signCount uint32) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?", int64(signCount), nowText(), id)
	return err
}

// RenamePasskey renames one of userID's passkeys.
func RenamePasskey(userID, id, name string) error {
	name = limitString(strings.TrimSpace(name), 64)
	if name == "" {
		return errors.New("give the passkey a name")
	}
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?", name, id, userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrUnknownPasskey
	}
	return nil
}

// RemovePasskey removes one of userID's passkeys. When two-step sign-in is
// required, it keeps the account's last way to sign in with more than a
// password.
func RemovePasskey(userID, id string) error {
	required, err := RequireMFA()
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
	var count int
	var app bool
	if err := tx.QueryRow("SELECT (SELECT COUNT(*) FROM passkeys WHERE user_id = ?), totp_secret != '' FROM users WHERE id = ?",
		userID, userID).Scan(&count, &app); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownUser
		}
		return err
	}
	if required && count <= 1 && !app {
		return ErrLastTwoStep
	}
	result, err := tx.Exec("DELETE FROM passkeys WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrUnknownPasskey
	}
	return tx.Commit()
}
