package store

import (
	"database/sql"
	"errors"
)

// PolicyRecord is a custom policy as stored; Source is its YAML.
type PolicyRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Enabled   bool   `json:"enabled"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

var ErrUnknownPolicy = errors.New("no such policy")

const policyColumns = "id, name, source, enabled, created_by, created_at, updated_at"

func scanPolicy(row rowScanner) (PolicyRecord, error) {
	var record PolicyRecord
	err := row.Scan(&record.ID, &record.Name, &record.Source, &record.Enabled, &record.CreatedBy, &record.CreatedAt, &record.UpdatedAt)
	return record, err
}

// ListPolicies returns every policy, oldest first.
func ListPolicies() ([]PolicyRecord, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + policyColumns + " FROM policies ORDER BY created_at, rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []PolicyRecord{}
	for rows.Next() {
		record, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetPolicy(id string) (PolicyRecord, error) {
	db, err := database()
	if err != nil {
		return PolicyRecord{}, err
	}
	record, err := scanPolicy(db.QueryRow("SELECT "+policyColumns+" FROM policies WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyRecord{}, ErrUnknownPolicy
	}
	return record, err
}

// AddPolicy stores a new, enabled policy.
func AddPolicy(name, source, createdBy string) (PolicyRecord, error) {
	db, err := database()
	if err != nil {
		return PolicyRecord{}, err
	}
	id, err := newID()
	if err != nil {
		return PolicyRecord{}, err
	}
	now := nowText()
	if _, err := db.Exec("INSERT INTO policies (id, name, source, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?)",
		id, name, source, createdBy, now, now); err != nil {
		return PolicyRecord{}, err
	}
	return GetPolicy(id)
}

// UpdatePolicy replaces a policy's YAML.
func UpdatePolicy(id, name, source string) (PolicyRecord, error) {
	return updatePolicy(id, "UPDATE policies SET name = ?, source = ?, updated_at = ? WHERE id = ?", name, source, nowText(), id)
}

// SetPolicyEnabled turns a policy on or off.
func SetPolicyEnabled(id string, enabled bool) (PolicyRecord, error) {
	return updatePolicy(id, "UPDATE policies SET enabled = ?, updated_at = ? WHERE id = ?", enabled, nowText(), id)
}

func updatePolicy(id, statement string, arguments ...any) (PolicyRecord, error) {
	db, err := database()
	if err != nil {
		return PolicyRecord{}, err
	}
	result, err := db.Exec(statement, arguments...)
	if err != nil {
		return PolicyRecord{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return PolicyRecord{}, ErrUnknownPolicy
	}
	return GetPolicy(id)
}

func DeletePolicy(id string) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("DELETE FROM policies WHERE id = ?", id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrUnknownPolicy
	}
	return nil
}
