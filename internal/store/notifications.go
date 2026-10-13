package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Channel is somewhere notifications go: an email address list, a Slack or
// Teams channel, or a webhook. Config is its settings as JSON, secrets
// included; the server never sends them back to the dashboard.
type Channel struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Config  string   `json:"-"`
	Enabled bool     `json:"enabled"`
	Events  []string `json:"events"`
	// Tags limits host events to hosts with any of these tags; empty is
	// every host.
	Tags []string `json:"tags"`
	// Digest is "", "daily" or "weekly"; a weekly one goes on DigestDays.
	Digest       string `json:"digest"`
	DigestDays   []int  `json:"digest_days"`
	DigestTime   string `json:"digest_time"`
	Timezone     string `json:"timezone"`
	NextDigestAt string `json:"next_digest_at"`
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

const channelColumns = `id, name, kind, config, enabled, events, tags, digest, digest_days, digest_time, timezone,
	next_digest_at, created_by, created_at, updated_at`

func splitList(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func scanChannel(row rowScanner) (Channel, error) {
	var channel Channel
	var events, tags, days string
	if err := row.Scan(&channel.ID, &channel.Name, &channel.Kind, &channel.Config, &channel.Enabled, &events, &tags,
		&channel.Digest, &days, &channel.DigestTime, &channel.Timezone, &channel.NextDigestAt,
		&channel.CreatedBy, &channel.CreatedAt, &channel.UpdatedAt); err != nil {
		return Channel{}, err
	}
	channel.Events, channel.Tags = splitList(events), splitList(tags)
	channel.DigestDays = []int{}
	for _, day := range splitList(days) {
		if value, err := strconv.Atoi(day); err == nil {
			channel.DigestDays = append(channel.DigestDays, value)
		}
	}
	return channel, nil
}

// Channels lists the notification channels by name.
func Channels() ([]Channel, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + channelColumns + " FROM notification_channels ORDER BY name COLLATE NOCASE, created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	channels := make([]Channel, 0)
	for rows.Next() {
		channel, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		channels = append(channels, channel)
	}
	return channels, rows.Err()
}

var ErrUnknownChannel = errors.New("unknown notification channel")

func GetChannel(id string) (Channel, error) {
	db, err := database()
	if err != nil {
		return Channel{}, err
	}
	channel, err := scanChannel(db.QueryRow("SELECT "+channelColumns+" FROM notification_channels WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrUnknownChannel
	}
	return channel, err
}

// SaveChannel creates channel when its ID is empty, or replaces it.
func SaveChannel(channel Channel) (Channel, error) {
	db, err := database()
	if err != nil {
		return Channel{}, err
	}
	now := nowText()
	days := make([]string, 0, len(channel.DigestDays))
	for _, day := range channel.DigestDays {
		days = append(days, strconv.Itoa(day))
	}
	if channel.ID == "" {
		if channel.ID, err = newID(); err != nil {
			return Channel{}, err
		}
		channel.CreatedAt = now
	}
	channel.UpdatedAt = now
	_, err = db.Exec(`INSERT INTO notification_channels (`+channelColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, config = excluded.config, enabled = excluded.enabled,
		events = excluded.events, tags = excluded.tags, digest = excluded.digest, digest_days = excluded.digest_days,
		digest_time = excluded.digest_time, timezone = excluded.timezone, next_digest_at = excluded.next_digest_at,
		updated_at = excluded.updated_at`,
		channel.ID, channel.Name, channel.Kind, channel.Config, channel.Enabled, strings.Join(channel.Events, ","),
		strings.Join(channel.Tags, ","), channel.Digest, strings.Join(days, ","), channel.DigestTime, channel.Timezone,
		channel.NextDigestAt, channel.CreatedBy, channel.CreatedAt, channel.UpdatedAt)
	if err != nil {
		return Channel{}, err
	}
	return GetChannel(channel.ID)
}

// DeleteChannel removes a channel and its deliveries.
func DeleteChannel(id string) (Channel, error) {
	channel, err := GetChannel(id)
	if err != nil {
		return Channel{}, err
	}
	db, err := database()
	if err != nil {
		return Channel{}, err
	}
	_, err = db.Exec("DELETE FROM notification_channels WHERE id = ?", id)
	return channel, err
}

// DueDigests lists the enabled channels whose digest is due at now.
func DueDigests(now time.Time) ([]Channel, error) {
	channels, err := Channels()
	if err != nil {
		return nil, err
	}
	due := make([]Channel, 0)
	stamp := now.UTC().Format(time.RFC3339)
	for _, channel := range channels {
		if channel.Enabled && channel.Digest != "" && channel.NextDigestAt != "" && channel.NextDigestAt <= stamp {
			due = append(due, channel)
		}
	}
	return due, nil
}

// SetNextDigest records when a channel's next digest is due.
func SetNextDigest(id, next string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE notification_channels SET next_digest_at = ? WHERE id = ?", next, id)
	return err
}

// Delivery states.
const (
	DeliveryPending = "pending"
	DeliverySent    = "sent"
	DeliveryFailed  = "failed"
)

// Delivery is one message to one channel, and how sending it went.
type Delivery struct {
	ID            int64  `json:"id"`
	ChannelID     string `json:"channel_id"`
	Event         string `json:"event"`
	Title         string `json:"title"`
	Message       string `json:"-"`
	Status        string `json:"status"`
	Attempts      int    `json:"attempts"`
	NextAttemptAt string `json:"next_attempt_at"`
	Error         string `json:"error"`
	CreatedAt     string `json:"created_at"`
	SentAt        string `json:"sent_at"`
}

const deliveryColumns = "id, channel_id, event, title, message, status, attempts, next_attempt_at, error, created_at, sent_at"

func scanDelivery(row rowScanner) (Delivery, error) {
	var delivery Delivery
	err := row.Scan(&delivery.ID, &delivery.ChannelID, &delivery.Event, &delivery.Title, &delivery.Message, &delivery.Status,
		&delivery.Attempts, &delivery.NextAttemptAt, &delivery.Error, &delivery.CreatedAt, &delivery.SentAt)
	return delivery, err
}

// EnqueueDelivery adds a message for a channel, to send now.
func EnqueueDelivery(channelID, event, title, message string) (int64, error) {
	db, err := database()
	if err != nil {
		return 0, err
	}
	now := nowText()
	result, err := db.Exec(`INSERT INTO notification_deliveries (channel_id, event, title, message, status, next_attempt_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, channelID, event, limitTitle(title), message, DeliveryPending, now, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func limitTitle(title string) string {
	if len(title) > 300 {
		return strings.ToValidUTF8(title[:300], "")
	}
	return title
}

// DueDeliveries returns pending deliveries whose time has come, oldest first.
func DueDeliveries(now time.Time, limit int) ([]Delivery, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT "+deliveryColumns+` FROM notification_deliveries
		WHERE status = ? AND next_attempt_at <= ? ORDER BY id LIMIT ?`, DeliveryPending, now.UTC().Format(time.RFC3339), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := make([]Delivery, 0)
	for rows.Next() {
		delivery, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

// DeliveryAttempted records an attempt: sent when sendErr is nil; otherwise
// pending until retryAt, or failed when retryAt is zero.
func DeliveryAttempted(id int64, sendErr error, retryAt time.Time) error {
	db, err := database()
	if err != nil {
		return err
	}
	now := nowText()
	switch {
	case sendErr == nil:
		_, err = db.Exec("UPDATE notification_deliveries SET status = ?, attempts = attempts + 1, error = '', sent_at = ? WHERE id = ?",
			DeliverySent, now, id)
	case retryAt.IsZero():
		_, err = db.Exec("UPDATE notification_deliveries SET status = ?, attempts = attempts + 1, error = ? WHERE id = ?",
			DeliveryFailed, limitTitle(sendErr.Error()), id)
	default:
		_, err = db.Exec("UPDATE notification_deliveries SET attempts = attempts + 1, error = ?, next_attempt_at = ? WHERE id = ?",
			limitTitle(sendErr.Error()), retryAt.UTC().Format(time.RFC3339), id)
	}
	return err
}

// GetDelivery returns one delivery.
func GetDelivery(id int64) (Delivery, error) {
	db, err := database()
	if err != nil {
		return Delivery{}, err
	}
	return scanDelivery(db.QueryRow("SELECT "+deliveryColumns+" FROM notification_deliveries WHERE id = ?", id))
}

// KeepDeliveries is how long the delivery log is kept.
const KeepDeliveries = 30 * 24 * time.Hour

// Deliveries lists a channel's deliveries, or every channel's when
// channelID is empty, newest first, after removing those older than
// KeepDeliveries.
func Deliveries(channelID string, limit int) ([]Delivery, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	since := time.Now().UTC().Add(-KeepDeliveries).Format(time.RFC3339)
	if _, err := db.Exec("DELETE FROM notification_deliveries WHERE created_at < ? AND status != ?", since, DeliveryPending); err != nil {
		return nil, err
	}
	query, arguments := "SELECT "+deliveryColumns+" FROM notification_deliveries", []any{}
	if channelID != "" {
		query += " WHERE channel_id = ?"
		arguments = append(arguments, channelID)
	}
	rows, err := db.Query(query+" ORDER BY id DESC LIMIT ?", append(arguments, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := make([]Delivery, 0)
	for rows.Next() {
		delivery, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

// Kinds of CVEs ScanCVEs returns.
const (
	CVEsExploited       = "exploited"        // in the KEV catalog
	CVEsCriticalFixable = "critical_fixable" // critical, with an update or restart that fixes it
)

var cveFilters = map[string]string{
	CVEsExploited:       "priority = 'exploited'",
	CVEsCriticalFixable: "severity = 'CRITICAL' AND fix IN ('available', 'reboot')",
}

// ScanCVEs returns the CVEs of one kind in a scan's package findings, for
// working out what is new since the previous scan.
func ScanCVEs(scanID, kind string) (map[string]bool, error) {
	filter, ok := cveFilters[kind]
	if !ok {
		return nil, fmt.Errorf("unknown kind of CVE %q", kind)
	}
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT DISTINCT cve FROM findings WHERE scan_id = ? AND "+filter, scanID)
	if err != nil {
		return nil, fmt.Errorf("read the scan's vulnerabilities: %w", err)
	}
	defer rows.Close()
	cves := make(map[string]bool)
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		cves[cve] = true
	}
	return cves, rows.Err()
}

// PreviousPackageScan returns the newest successful scan of host that
// checked packages and started before scan, if any.
func PreviousPackageScan(scan Scan) (Scan, bool, error) {
	db, err := database()
	if err != nil {
		return Scan{}, false, err
	}
	previous, err := scanScan(db.QueryRow("SELECT "+scanColumns+` FROM scans
		WHERE host_id = ? AND id != ? AND status = ? AND checks LIKE ? AND started_at <= ?
		ORDER BY started_at DESC, rowid DESC LIMIT 1`, scan.HostID, scan.ID, ScanSucceeded, "%,"+CheckPackages+",%", scan.StartedAt))
	if errors.Is(err, sql.ErrNoRows) {
		return Scan{}, false, nil
	}
	return previous, err == nil, err
}

// CheckCount is how many findings one check of a scan had, and how many of
// them were critical or high.
type CheckCount struct {
	Findings int
	Severe   int
}

// ScanCheckCounts returns each check's finding counts in a scan.
func ScanCheckCounts(scanID string) (map[string]CheckCount, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT check_id, finding_count, critical + high FROM scan_checks WHERE scan_id = ? AND status != 'failed' AND status != 'skipped'", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]CheckCount)
	for rows.Next() {
		var check string
		var count CheckCount
		if err := rows.Scan(&check, &count.Findings, &count.Severe); err != nil {
			return nil, err
		}
		counts[check] = count
	}
	return counts, rows.Err()
}

// LatestFinding is one vulnerable package in a host's latest scan.
type LatestFinding struct {
	CVE string
	AffectedPackage
}

// LatestFindings lists the vulnerable packages in every host's latest scan
// that checked packages, by host and package.
func LatestFindings() ([]LatestFinding, error) {
	affected, cves, err := queryLatestFindings("")
	if err != nil {
		return nil, err
	}
	result := make([]LatestFinding, len(affected))
	for index := range affected {
		result[index] = LatestFinding{CVE: cves[index], AffectedPackage: affected[index]}
	}
	return result, nil
}
