package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

// ReportRecord is a report's details, without its snapshot.
type ReportRecord struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	HostID      string `json:"host_id"`
	Kind        string `json:"kind"`
	Client      string `json:"client"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	Fingerprint string `json:"fingerprint"`
}

var ErrUnknownReport = errors.New("no such report")

// NewReportID returns an ID for a report about to be built.
func NewReportID() (string, error) { return newID() }

// SaveReportSnapshot stores a frozen report.
func SaveReportSnapshot(record ReportRecord, snapshot []byte) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO reports (id, scan_id, host_id, kind, client, created_by, created_at, fingerprint, snapshot)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, record.ScanID, record.HostID, record.Kind, limitString(record.Client, 200),
		record.CreatedBy, record.CreatedAt, record.Fingerprint, snapshot)
	return err
}

const reportColumns = "id, scan_id, host_id, kind, client, created_by, created_at, fingerprint"

func scanReportRecord(row rowScanner) (ReportRecord, error) {
	var record ReportRecord
	err := row.Scan(&record.ID, &record.ScanID, &record.HostID, &record.Kind, &record.Client, &record.CreatedBy, &record.CreatedAt, &record.Fingerprint)
	return record, err
}

// ListReports returns reports, newest first, for a scan, or else for a
// host, or else all of them.
func ListReports(scanID, hostID string) ([]ReportRecord, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	query, arguments := "SELECT "+reportColumns+" FROM reports", []any{}
	switch {
	case scanID != "":
		query += " WHERE scan_id = ?"
		arguments = append(arguments, scanID)
	case hostID != "":
		query += " WHERE host_id = ?"
		arguments = append(arguments, hostID)
	}
	rows, err := db.Query(query+" ORDER BY created_at DESC, rowid DESC LIMIT 500", arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []ReportRecord{}
	for rows.Next() {
		record, err := scanReportRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// GetReportSnapshot returns a report and its frozen snapshot.
func GetReportSnapshot(id string) (ReportRecord, []byte, error) {
	db, err := database()
	if err != nil {
		return ReportRecord{}, nil, err
	}
	var record ReportRecord
	var snapshot []byte
	err = db.QueryRow("SELECT "+reportColumns+", snapshot FROM reports WHERE id = ?", id).Scan(&record.ID, &record.ScanID, &record.HostID,
		&record.Kind, &record.Client, &record.CreatedBy, &record.CreatedAt, &record.Fingerprint, &snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return ReportRecord{}, nil, ErrUnknownReport
	}
	return record, snapshot, err
}

// DeleteReport removes a report and its share links.
func DeleteReport(id string) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("DELETE FROM reports WHERE id = ?", id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrUnknownReport
	}
	return nil
}

// Share is a link that shows a report without sign-in until it expires.
type Share struct {
	ID        string `json:"id"`
	ReportID  string `json:"report_id"`
	ExpiresAt string `json:"expires_at"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	RevokedAt string `json:"revoked_at"`
	Views     int    `json:"views"`
}

// Active reports whether the link still opens at now.
func (s Share) Active(now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, s.ExpiresAt)
	return s.RevokedAt == "" && err == nil && now.Before(expires)
}

var ErrUnknownShare = errors.New("this link doesn't exist, has expired, or was revoked")

// CreateShare makes a link to a report; the token is returned only now and
// stored only as a hash.
func CreateShare(reportID string, lifetime time.Duration, createdBy string) (Share, string, error) {
	if _, _, err := GetReportSnapshot(reportID); err != nil {
		return Share{}, "", err
	}
	db, err := database()
	if err != nil {
		return Share{}, "", err
	}
	id, err := newID()
	if err != nil {
		return Share{}, "", err
	}
	token, err := NewSecret()
	if err != nil {
		return Share{}, "", err
	}
	now := time.Now().UTC()
	share := Share{ID: id, ReportID: reportID, ExpiresAt: now.Add(lifetime).Format(time.RFC3339), CreatedBy: createdBy, CreatedAt: now.Format(time.RFC3339)}
	_, err = db.Exec(`INSERT INTO report_shares (id, report_id, token_hash, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		share.ID, share.ReportID, HashSecret(token), share.ExpiresAt, share.CreatedBy, share.CreatedAt)
	return share, token, err
}

const shareColumns = "id, report_id, expires_at, created_by, created_at, revoked_at, views"

func scanShare(row rowScanner) (Share, error) {
	var share Share
	err := row.Scan(&share.ID, &share.ReportID, &share.ExpiresAt, &share.CreatedBy, &share.CreatedAt, &share.RevokedAt, &share.Views)
	return share, err
}

// Shares lists a report's links, newest first.
func Shares(reportID string) ([]Share, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT "+shareColumns+" FROM report_shares WHERE report_id = ? ORDER BY created_at DESC", reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	shares := []Share{}
	for rows.Next() {
		share, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, rows.Err()
}

// OpenShare finds an active link by its token and counts the view.
func OpenShare(token string, count bool) (Share, error) {
	db, err := database()
	if err != nil {
		return Share{}, err
	}
	share, err := scanShare(db.QueryRow("SELECT "+shareColumns+" FROM report_shares WHERE token_hash = ?", HashSecret(token)))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !share.Active(time.Now())) {
		return Share{}, ErrUnknownShare
	}
	if err != nil {
		return Share{}, err
	}
	if count {
		db.Exec("UPDATE report_shares SET views = views + 1 WHERE id = ?", share.ID)
		share.Views++
	}
	return share, nil
}

// RevokeShare stops a link from opening.
func RevokeShare(id string) (Share, error) {
	db, err := database()
	if err != nil {
		return Share{}, err
	}
	share, err := scanShare(db.QueryRow("SELECT "+shareColumns+" FROM report_shares WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrUnknownShare
	}
	if err != nil {
		return Share{}, err
	}
	if share.RevokedAt == "" {
		share.RevokedAt = nowText()
		_, err = db.Exec("UPDATE report_shares SET revoked_at = ? WHERE id = ?", share.RevokedAt, id)
	}
	return share, err
}

// ReportBranding is what admins set for every report.
type ReportBranding struct {
	Company  string `json:"company"`
	Contact  string `json:"contact"`
	Logo     []byte `json:"-"`
	LogoType string `json:"logo_type"`
}

const (
	metaReportCompany  = "report_company"
	metaReportContact  = "report_contact"
	metaReportLogo     = "report_logo"
	metaReportLogoType = "report_logo_type"
)

func GetReportBranding() (ReportBranding, error) {
	var branding ReportBranding
	var logo string
	for key, target := range map[string]*string{metaReportCompany: &branding.Company, metaReportContact: &branding.Contact,
		metaReportLogo: &logo, metaReportLogoType: &branding.LogoType} {
		value, err := Meta(key)
		if err != nil {
			return ReportBranding{}, err
		}
		*target = value
	}
	if logo != "" {
		decoded, err := base64.StdEncoding.DecodeString(logo)
		if err != nil {
			return ReportBranding{}, err
		}
		branding.Logo = decoded
	}
	return branding, nil
}

// SetReportText saves the company name and contact line.
func SetReportText(company, contact string) error {
	if err := SetMeta(metaReportCompany, limitString(company, 120)); err != nil {
		return err
	}
	return SetMeta(metaReportContact, limitString(contact, 200))
}

// SetReportLogo saves the logo; nil removes it.
func SetReportLogo(logo []byte, contentType string) error {
	if len(logo) == 0 {
		contentType = ""
	}
	if err := SetMeta(metaReportLogo, base64.StdEncoding.EncodeToString(logo)); err != nil {
		return err
	}
	return SetMeta(metaReportLogoType, contentType)
}
