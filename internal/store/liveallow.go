package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"deaconguard/internal/live"
)

// MaxLiveAllow bounds the allowlist rules kept.
const MaxLiveAllow = 500

// LiveAllow is an allowlist rule as Settings shows it.
type LiveAllow struct {
	live.Allow
	// HostID is the host or cluster it applies to, or "" for every host;
	// Scope names it.
	HostID    string    `json:"host_id"`
	Scope     string    `json:"scope"`
	Note      string    `json:"note"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Skipped counts the alerts it skipped, on every host, and LastAt is
	// when it last skipped one.
	Skipped uint64     `json:"skipped"`
	LastAt  *time.Time `json:"last_at,omitempty"`
}

// ErrLiveAllowNotFound is returned for a rule that doesn't exist.
var ErrLiveAllowNotFound = errors.New("no such allowlist rule")

var liveRuleID = regexp.MustCompile(`^DG-RT-[0-9]{3}$`)

// Validate checks a rule before it's saved: a rule ID, and at least one of
// the program, path, image, container or namespace, so a rule never turns
// off a whole kind of alert.
func (a LiveAllow) Validate() error {
	if !liveRuleID.MatchString(a.Rule) {
		return fmt.Errorf("rule must be a live detection rule ID, such as %s", live.RuleTempProgram)
	}
	if a.Program == "" && a.Path == "" && a.Image == "" && a.Container == "" && a.Namespace == "" {
		return errors.New("name at least one of the program, path, image, container or namespace, so the rule doesn't skip every alert of its kind")
	}
	for name, value := range map[string]string{"program": a.Program, "path": a.Path, "image": a.Image, "container": a.Container, "namespace": a.Namespace} {
		if len(value) > 512 || strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("%s is too long or has line breaks", name)
		}
	}
	if len(a.Note) > 500 {
		return errors.New("the note is longer than 500 characters")
	}
	if a.HostID != "" {
		if _, err := GetHost(a.HostID); err != nil {
			return fmt.Errorf("unknown host ID: %s", a.HostID)
		}
	}
	return nil
}

// ListLiveAllow lists the allowlist rules, newest first, with what each
// skipped. Rules for hosts that were removed go with them.
func ListLiveAllow() ([]LiveAllow, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("DELETE FROM live_allow WHERE host_id != '' AND NOT EXISTS (SELECT 1 FROM hosts h WHERE h.id = live_allow.host_id)"); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT a.id, a.host_id, COALESCE(CASE WHEN h.display_name != '' THEN h.display_name ELSE h.address END, ''),
			a.rule, a.program, a.path, a.image, a.container, a.namespace, a.note, a.created_by, a.created_at, a.updated_at,
			COALESCE((SELECT SUM(skipped) FROM live_allow_hits WHERE allow_id = a.id), 0),
			COALESCE((SELECT MAX(last_at) FROM live_allow_hits WHERE allow_id = a.id), '')
		FROM live_allow a LEFT JOIN hosts h ON h.id = a.host_id ORDER BY a.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []LiveAllow{}
	for rows.Next() {
		var rule LiveAllow
		var created, updated, last string
		if err := rows.Scan(&rule.ID, &rule.HostID, &rule.Scope, &rule.Rule, &rule.Program, &rule.Path, &rule.Image, &rule.Container,
			&rule.Namespace, &rule.Note, &rule.CreatedBy, &created, &updated, &rule.Skipped, &last); err != nil {
			return nil, err
		}
		rule.CreatedAt, _ = time.Parse(time.RFC3339, created)
		rule.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		if at, err := time.Parse(time.RFC3339, last); err == nil {
			rule.LastAt = &at
		}
		if rule.HostID == "" {
			rule.Scope = "All hosts"
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// GetLiveAllow returns one rule.
func GetLiveAllow(id int64) (LiveAllow, error) {
	rules, err := ListLiveAllow()
	if err != nil {
		return LiveAllow{}, err
	}
	for _, rule := range rules {
		if rule.ID == id {
			return rule, nil
		}
	}
	return LiveAllow{}, ErrLiveAllowNotFound
}

// CreateLiveAllow saves a new rule and returns its ID.
func CreateLiveAllow(rule LiveAllow, by string, now time.Time) (int64, error) {
	if err := rule.Validate(); err != nil {
		return 0, err
	}
	db, err := database()
	if err != nil {
		return 0, err
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM live_allow").Scan(&count); err != nil {
		return 0, err
	}
	if count >= MaxLiveAllow {
		return 0, fmt.Errorf("the allowlist holds at most %d rules; remove some first", MaxLiveAllow)
	}
	at := now.UTC().Format(time.RFC3339)
	result, err := db.Exec(`INSERT INTO live_allow (host_id, rule, program, path, image, container, namespace, note, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, rule.HostID, rule.Rule, rule.Program, rule.Path, rule.Image, rule.Container, rule.Namespace,
		rule.Note, by, at, at)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// UpdateLiveAllow changes a rule. What it skipped so far is kept.
func UpdateLiveAllow(rule LiveAllow, now time.Time) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec(`UPDATE live_allow SET host_id = ?, rule = ?, program = ?, path = ?, image = ?, container = ?, namespace = ?, note = ?, updated_at = ?
		WHERE id = ?`, rule.HostID, rule.Rule, rule.Program, rule.Path, rule.Image, rule.Container, rule.Namespace, rule.Note,
		now.UTC().Format(time.RFC3339), rule.ID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrLiveAllowNotFound
	}
	return nil
}

// DeleteLiveAllow removes a rule.
func DeleteLiveAllow(id int64) error {
	db, err := database()
	if err != nil {
		return err
	}
	result, err := db.Exec("DELETE FROM live_allow WHERE id = ?", id)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrLiveAllowNotFound
	}
	return nil
}

// LiveAllowFor returns the rules that apply to a host: those for every
// host, for the host itself, and for its cluster.
func LiveAllowFor(hostID string) ([]live.Allow, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT id, rule, program, path, image, container, namespace FROM live_allow
		WHERE host_id = '' OR host_id = ? OR host_id = (SELECT cluster_id FROM hosts WHERE id = ? AND cluster_id != '')
		ORDER BY id LIMIT ?`, hostID, hostID, MaxLiveAllow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []live.Allow{}
	for rows.Next() {
		var rule live.Allow
		if err := rows.Scan(&rule.ID, &rule.Rule, &rule.Program, &rule.Path, &rule.Image, &rule.Container, &rule.Namespace); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// CountLiveAllowed adds what the rules skipped on a host. Counts for rules
// that were removed meanwhile are dropped.
func CountLiveAllowed(hostID string, skipped map[int64]uint64, now time.Time) error {
	if len(skipped) == 0 {
		return nil
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
	at := now.UTC().Format(time.RFC3339)
	for id, count := range skipped {
		if count == 0 {
			continue
		}
		var exists int
		if err := tx.QueryRow("SELECT 1 FROM live_allow WHERE id = ?", id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO live_allow_hits (allow_id, host_id, skipped, last_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (allow_id, host_id) DO UPDATE SET skipped = skipped + excluded.skipped, last_at = excluded.last_at`,
			id, hostID, count, at); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LiveAllowSummary is what the allowlist does on one host (or a cluster's
// nodes), for its Runtime tab.
type LiveAllowSummary struct {
	Rules   int        `json:"rules"`
	Skipped uint64     `json:"skipped"`
	LastAt  *time.Time `json:"last_at,omitempty"`
}

// HostLiveAllow summarizes the rules that apply to a host and what they
// skipped there; for a cluster, on all its nodes.
func HostLiveAllow(host Host) (LiveAllowSummary, error) {
	var summary LiveAllowSummary
	db, err := database()
	if err != nil {
		return summary, err
	}
	hosts := "host_id = ?"
	if host.IsCluster() {
		hosts = "host_id IN (SELECT id FROM hosts WHERE cluster_id = ?)"
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM live_allow WHERE host_id = '' OR host_id = ? OR host_id = ?`, host.ID, host.ClusterID).Scan(&summary.Rules); err != nil {
		return summary, err
	}
	var last string
	if err := db.QueryRow(`SELECT COALESCE(SUM(skipped), 0), COALESCE(MAX(last_at), '') FROM live_allow_hits WHERE `+hosts, host.ID).Scan(&summary.Skipped, &last); err != nil {
		return summary, err
	}
	if at, err := time.Parse(time.RFC3339, last); err == nil {
		summary.LastAt = &at
	}
	return summary, nil
}
