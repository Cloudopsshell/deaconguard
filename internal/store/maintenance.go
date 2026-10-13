package store

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
)

// MaintenanceWindow is a time when hosts are expected to misbehave, such as
// while they are patched and restarted: notifications about them are held
// back, and their scheduled scans can be skipped. Tags limits it to hosts
// with any of them; empty is every host.
type MaintenanceWindow struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Tags      []string `json:"tags"`
	StartsAt  string   `json:"starts_at"`
	EndsAt    string   `json:"ends_at"`
	SkipScans bool     `json:"skip_scans"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
	// Status is upcoming, active or ended.
	Status string `json:"status"`
}

// MaxMaintenance is the longest a window lasts.
const MaxMaintenance = 7 * 24 * time.Hour

const maintenanceColumns = "id, name, tags, starts_at, ends_at, skip_scans, created_by, created_at"

func scanWindow(row rowScanner, now time.Time) (MaintenanceWindow, error) {
	var window MaintenanceWindow
	var tags string
	if err := row.Scan(&window.ID, &window.Name, &tags, &window.StartsAt, &window.EndsAt, &window.SkipScans, &window.CreatedBy, &window.CreatedAt); err != nil {
		return MaintenanceWindow{}, err
	}
	window.Tags = splitList(tags)
	stamp := now.UTC().Format(time.RFC3339)
	switch {
	case stamp < window.StartsAt:
		window.Status = "upcoming"
	case stamp < window.EndsAt:
		window.Status = "active"
	default:
		window.Status = "ended"
	}
	return window, nil
}

// MaintenanceWindows lists the windows, soonest first, after removing those
// that ended more than 30 days ago.
func MaintenanceWindows(now time.Time) ([]MaintenanceWindow, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("DELETE FROM maintenance_windows WHERE ends_at < ?", now.UTC().Add(-30*24*time.Hour).Format(time.RFC3339)); err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + maintenanceColumns + " FROM maintenance_windows ORDER BY starts_at, created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	windows := make([]MaintenanceWindow, 0)
	for rows.Next() {
		window, err := scanWindow(rows, now)
		if err != nil {
			return nil, err
		}
		windows = append(windows, window)
	}
	return windows, rows.Err()
}

// AddMaintenanceWindow checks and saves a new window.
func AddMaintenanceWindow(window MaintenanceWindow, now time.Time) (MaintenanceWindow, error) {
	window.Name = strings.TrimSpace(window.Name)
	if window.Name == "" || len(window.Name) > 80 || strings.ContainsFunc(window.Name, unicode.IsControl) {
		return MaintenanceWindow{}, errors.New("give the window a name of up to 80 characters")
	}
	starts, err := time.Parse(time.RFC3339, window.StartsAt)
	if err != nil {
		return MaintenanceWindow{}, errors.New("give when the window starts")
	}
	ends, err := time.Parse(time.RFC3339, window.EndsAt)
	if err != nil || !ends.After(starts) {
		return MaintenanceWindow{}, errors.New("the window must end after it starts")
	}
	if ends.Sub(starts) > MaxMaintenance {
		return MaintenanceWindow{}, errors.New("a window lasts at most 7 days")
	}
	if !ends.After(now) {
		return MaintenanceWindow{}, errors.New("the window has already ended")
	}
	if window.Tags, err = NormalizeTags(window.Tags); err != nil {
		return MaintenanceWindow{}, err
	}
	if window.ID, err = newID(); err != nil {
		return MaintenanceWindow{}, err
	}
	window.StartsAt, window.EndsAt = starts.UTC().Format(time.RFC3339), ends.UTC().Format(time.RFC3339)
	window.CreatedAt = nowText()
	db, err := database()
	if err != nil {
		return MaintenanceWindow{}, err
	}
	if _, err := db.Exec("INSERT INTO maintenance_windows ("+maintenanceColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		window.ID, window.Name, strings.Join(window.Tags, ","), window.StartsAt, window.EndsAt, window.SkipScans, window.CreatedBy, window.CreatedAt); err != nil {
		return MaintenanceWindow{}, err
	}
	return scanWindow(db.QueryRow("SELECT "+maintenanceColumns+" FROM maintenance_windows WHERE id = ?", window.ID), now)
}

var ErrUnknownWindow = errors.New("unknown maintenance window")

// DeleteMaintenanceWindow removes a window, ending it at once if it is active.
func DeleteMaintenanceWindow(id string) (MaintenanceWindow, error) {
	db, err := database()
	if err != nil {
		return MaintenanceWindow{}, err
	}
	window, err := scanWindow(db.QueryRow("SELECT "+maintenanceColumns+" FROM maintenance_windows WHERE id = ?", id), time.Now())
	if errors.Is(err, sql.ErrNoRows) {
		return MaintenanceWindow{}, ErrUnknownWindow
	}
	if err != nil {
		return MaintenanceWindow{}, err
	}
	_, err = db.Exec("DELETE FROM maintenance_windows WHERE id = ?", id)
	return window, err
}

// InMaintenance returns the active window covering a host with tags, if any.
func InMaintenance(tags []string, now time.Time) (MaintenanceWindow, bool, error) {
	windows, err := MaintenanceWindows(now)
	if err != nil {
		return MaintenanceWindow{}, false, err
	}
	for _, window := range windows {
		if window.Status != "active" {
			continue
		}
		if len(window.Tags) == 0 || slices.ContainsFunc(window.Tags, func(tag string) bool { return slices.Contains(tags, tag) }) {
			return window, true, nil
		}
	}
	return MaintenanceWindow{}, false, nil
}

// HostTags returns one host's tags.
func HostTags(hostID string) ([]string, error) {
	tags, err := hostTags()
	if err != nil {
		return nil, err
	}
	return tags[hostID], nil
}
