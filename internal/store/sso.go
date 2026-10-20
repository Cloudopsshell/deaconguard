package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// SSOConfig is how the dashboard signs people in with an OpenID Connect
// provider. ClientSecret is never sent back to the dashboard.
type SSOConfig struct {
	Enabled      bool   `json:"enabled"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	// ButtonLabel is the sign-in button's text, such as "Sign in with Entra ID".
	ButtonLabel string `json:"button_label"`
	// UsernameClaim names new accounts: "email" or "preferred_username".
	UsernameClaim string `json:"username_claim"`
	// GroupsClaim is the claim that lists a person's groups, often "groups".
	GroupsClaim string `json:"groups_claim"`
	// Scopes are asked for besides openid, email and profile, such as
	// "groups", which Dex and Okta need to send groups.
	Scopes []string `json:"scopes"`
	// AllowedDomains, when set, admit only verified emails in them.
	AllowedDomains []string `json:"allowed_domains"`
	// AllowedGroups, when set, admit only members of them, of AdminGroups or
	// of OperatorGroups.
	AllowedGroups []string `json:"allowed_groups"`
	// AdminGroups and OperatorGroups give their members that role, at every
	// sign-in; everyone else gets DefaultRole.
	AdminGroups    []string `json:"admin_groups"`
	OperatorGroups []string `json:"operator_groups"`
	DefaultRole    string   `json:"default_role"`
}

// metaSSO holds the SSOConfig, as JSON.
const metaSSO = "sso"

// LoadSSOConfig returns the single sign-on settings, with defaults.
func LoadSSOConfig() (SSOConfig, error) {
	config := SSOConfig{UsernameClaim: "email", GroupsClaim: "groups", DefaultRole: RoleViewer}
	value, err := Meta(metaSSO)
	if err != nil || value == "" {
		return config, err
	}
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return config, err
	}
	return config, nil
}

// SaveSSOConfig saves the single sign-on settings.
func SaveSSOConfig(config SSOConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return SetMeta(metaSSO, string(data))
}

// ErrSSOUsernameTaken: a password account has the name single sign-on would give.
var ErrSSOUsernameTaken = errors.New("an account with this name already exists and doesn't use single sign-on")

// UserBySSOSubject finds the account linked to a provider's issuer and subject.
func UserBySSOSubject(subject string) (User, error) {
	db, err := database()
	if err != nil {
		return User{}, err
	}
	user, err := scanUser(db.QueryRow("SELECT "+userColumns+" FROM users u WHERE u.oidc_subject = ?", subject))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUnknownUser
	}
	return user, err
}

// AddSSOUser creates an account that signs in with single sign-on only: it
// has no password.
func AddSSOUser(username, role, subject string) (User, error) {
	if !ValidRole(role) {
		return User{}, ErrUnknownRole
	}
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
	db, err := database()
	if err != nil {
		return User{}, err
	}
	id, err := newID()
	if err != nil {
		return User{}, err
	}
	if _, err := db.Exec("INSERT INTO users (id, username, password_hash, created_at, role, oidc_subject) VALUES (?, ?, '', ?, ?, ?)",
		id, username, nowText(), role, subject); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrSSOUsernameTaken
		}
		return User{}, err
	}
	return GetUser(id)
}
