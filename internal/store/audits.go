package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MarkAudit records that a scan is a handover audit, which is graded and
// kept until someone deletes it.
func MarkAudit(scanID string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE scans SET audit = 1 WHERE id = ?", scanID)
	return err
}

// ListAudits returns audits, newest first, for one host or, with hostID
// empty, for every host.
func ListAudits(hostID string, limit int) ([]Scan, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	query := "SELECT " + scanColumns + " FROM scans WHERE audit = 1"
	arguments := []any{}
	if hostID != "" {
		query += " AND host_id = ?"
		arguments = append(arguments, hostID)
	}
	query += " ORDER BY started_at DESC, rowid DESC LIMIT ?"
	arguments = append(arguments, limit)
	rows, err := db.Query(query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	audits := []Scan{}
	for rows.Next() {
		scan, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		audits = append(audits, scan)
	}
	return audits, rows.Err()
}

// Exception is a failed control an admin accepted, for one host or, with
// HostID empty, for every host.
type Exception struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	ControlID string `json:"control_id"`
	Reason    string `json:"reason"`
	// ExpiresAt is empty for an exception that doesn't expire.
	ExpiresAt string `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

// Active reports whether the exception still applies at now.
func (e Exception) Active(now time.Time) bool {
	if e.ExpiresAt == "" {
		return true
	}
	expires, err := time.Parse(time.RFC3339, e.ExpiresAt)
	return err == nil && now.Before(expires)
}

var ErrUnknownException = errors.New("no such accepted risk")

// AddException accepts the risk of a failed control. expiresAt is RFC 3339
// or empty.
func AddException(hostID, controlID, reason, expiresAt, createdBy string) (Exception, error) {
	reason = strings.TrimSpace(reason)
	if controlID == "" || len(controlID) > 64 {
		return Exception{}, fmt.Errorf("choose a control")
	}
	if reason == "" {
		return Exception{}, fmt.Errorf("give a reason, so others know why the risk was accepted")
	}
	if expiresAt != "" {
		expires, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return Exception{}, fmt.Errorf("the expiry date is not valid")
		}
		if !expires.After(time.Now()) {
			return Exception{}, fmt.Errorf("the expiry date must be in the future")
		}
		expiresAt = expires.UTC().Format(time.RFC3339)
	}
	if hostID != "" {
		if _, err := GetHost(hostID); err != nil {
			return Exception{}, err
		}
	}
	db, err := database()
	if err != nil {
		return Exception{}, err
	}
	id, err := newID()
	if err != nil {
		return Exception{}, err
	}
	exception := Exception{ID: id, HostID: hostID, ControlID: controlID, Reason: limitString(reason, 1000), ExpiresAt: expiresAt,
		CreatedBy: createdBy, CreatedAt: nowText()}
	_, err = db.Exec(`INSERT INTO audit_exceptions (id, host_id, control_id, reason, expires_at, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, exception.ID, exception.HostID, exception.ControlID, exception.Reason, exception.ExpiresAt,
		exception.CreatedBy, exception.CreatedAt)
	return exception, err
}

// Exceptions returns the accepted risks that apply to a host: its own and
// those for every host. With hostID empty, it returns all of them.
func Exceptions(hostID string) ([]Exception, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	query := "SELECT id, host_id, control_id, reason, expires_at, created_by, created_at FROM audit_exceptions"
	arguments := []any{}
	if hostID != "" {
		query += " WHERE host_id = ? OR host_id = ''"
		arguments = append(arguments, hostID)
	}
	rows, err := db.Query(query+" ORDER BY created_at DESC", arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	exceptions := []Exception{}
	for rows.Next() {
		var exception Exception
		if err := rows.Scan(&exception.ID, &exception.HostID, &exception.ControlID, &exception.Reason, &exception.ExpiresAt,
			&exception.CreatedBy, &exception.CreatedAt); err != nil {
			return nil, err
		}
		exceptions = append(exceptions, exception)
	}
	return exceptions, rows.Err()
}

// GetException returns one accepted risk.
func GetException(id string) (Exception, error) {
	db, err := database()
	if err != nil {
		return Exception{}, err
	}
	var exception Exception
	err = db.QueryRow("SELECT id, host_id, control_id, reason, expires_at, created_by, created_at FROM audit_exceptions WHERE id = ?", id).
		Scan(&exception.ID, &exception.HostID, &exception.ControlID, &exception.Reason, &exception.ExpiresAt, &exception.CreatedBy, &exception.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Exception{}, ErrUnknownException
	}
	return exception, err
}

// RemoveException withdraws an accepted risk.
func RemoveException(id string) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("DELETE FROM audit_exceptions WHERE id = ?", id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrUnknownException
	}
	return nil
}

// metaAuditOnEnroll holds whether newly enrolled machines are audited.
const metaAuditOnEnroll = "audit_on_enroll"

// AuditOnEnroll reports whether a machine is audited when its agent enrolls.
func AuditOnEnroll() (bool, error) {
	value, err := Meta(metaAuditOnEnroll)
	return value == "1", err
}

func SetAuditOnEnroll(on bool) error {
	value := ""
	if on {
		value = "1"
	}
	return SetMeta(metaAuditOnEnroll, value)
}
