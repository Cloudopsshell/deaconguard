package store

import "strings"

// HostKey is an SSH key an account on a host trusts, as its fingerprint,
// from the host's latest attack path check (1.26.0 and later).
type HostKey struct {
	HostID      string
	Host        string
	Account     string
	Fingerprint string
	Root        bool
	Text        string
}

// SetHostKeys replaces the SSH keys a host's accounts trust.
func SetHostKeys(hostID string, keys []HostKey) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM host_ssh_keys WHERE host_id = ?`, hostID); err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO host_ssh_keys (host_id, account, fingerprint, root, text) VALUES (?, ?, ?, ?, ?)`,
			hostID, key.Account, key.Fingerprint, key.Root, key.Text); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// KeyHosts lists the other hosts that trust each of fingerprints, with the
// account that trusts it, by host name.
func KeyHosts(hostID string, fingerprints []string) (map[string][]HostKey, error) {
	result := map[string][]HostKey{}
	if len(fingerprints) == 0 {
		return result, nil
	}
	db, err := database()
	if err != nil {
		return nil, err
	}
	arguments := []any{hostID}
	for _, fingerprint := range fingerprints {
		arguments = append(arguments, fingerprint)
	}
	rows, err := db.Query(`SELECT k.host_id, CASE WHEN h.display_name != '' THEN h.display_name ELSE h.address END, k.account, k.fingerprint, k.root, k.text
		FROM host_ssh_keys k JOIN hosts h ON h.id = k.host_id
		WHERE k.host_id != ? AND k.fingerprint IN (?`+strings.Repeat(", ?", len(fingerprints)-1)+`)
		ORDER BY 2, k.account`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key HostKey
		if err := rows.Scan(&key.HostID, &key.Host, &key.Account, &key.Fingerprint, &key.Root, &key.Text); err != nil {
			return nil, err
		}
		result[key.Fingerprint] = append(result[key.Fingerprint], key)
	}
	return result, rows.Err()
}
