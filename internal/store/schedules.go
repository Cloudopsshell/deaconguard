package store

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Schedule runs scans of its hosts on chosen days at a time of day.
type Schedule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Checks  []string `json:"checks"`
	// AllHosts includes every host, including those added later; otherwise
	// HostIDs lists the hosts.
	AllHosts bool     `json:"all_hosts"`
	HostIDs  []string `json:"host_ids"`
	// Days are days of the week, Sunday being 0.
	Days     []int  `json:"days"`
	Time     string `json:"time"`
	Timezone string `json:"timezone"`
	// NextRunAt is when it runs next, empty while it is disabled.
	NextRunAt string `json:"next_run_at"`
	LastRunAt string `json:"last_run_at"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// ErrScheduleNotFound means no schedule has the ID.
var ErrScheduleNotFound = errors.New("unknown schedule")

const scheduleColumns = `id, name, enabled, checks, all_hosts, host_ids, days, time, timezone, next_run_at, last_run_at, created_at, created_by`

func scanSchedule(row rowScanner) (Schedule, error) {
	var schedule Schedule
	var checks, hosts, days string
	if err := row.Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &checks, &schedule.AllHosts, &hosts, &days,
		&schedule.Time, &schedule.Timezone, &schedule.NextRunAt, &schedule.LastRunAt, &schedule.CreatedAt, &schedule.CreatedBy); err != nil {
		return Schedule{}, err
	}
	schedule.Checks = decodeChecks(checks)
	schedule.HostIDs = decodeChecks(hosts)
	schedule.Days = make([]int, 0, 7)
	for _, value := range decodeChecks(days) {
		if day, err := strconv.Atoi(value); err == nil {
			schedule.Days = append(schedule.Days, day)
		}
	}
	return schedule, nil
}

func encodeDays(days []int) string {
	values := make([]string, 0, len(days))
	for _, day := range days {
		values = append(values, strconv.Itoa(day))
	}
	return encodeChecks(values)
}

// Schedules lists every schedule, by name.
func Schedules() ([]Schedule, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + scheduleColumns + " FROM schedules ORDER BY name COLLATE NOCASE, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	schedules := make([]Schedule, 0)
	for rows.Next() {
		schedule, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

// GetSchedule returns one schedule.
func GetSchedule(id string) (Schedule, error) {
	db, err := database()
	if err != nil {
		return Schedule{}, err
	}
	schedule, err := scanSchedule(db.QueryRow("SELECT "+scheduleColumns+" FROM schedules WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, ErrScheduleNotFound
	}
	return schedule, err
}

// SaveSchedule adds a schedule without an ID, or replaces the one with its ID,
// and returns it as stored.
func SaveSchedule(schedule Schedule) (Schedule, error) {
	db, err := database()
	if err != nil {
		return Schedule{}, err
	}
	if !schedule.Enabled {
		schedule.NextRunAt = ""
	}
	if schedule.ID == "" {
		if schedule.ID, err = newID(); err != nil {
			return Schedule{}, err
		}
		schedule.CreatedAt = nowText()
		_, err = db.Exec("INSERT INTO schedules ("+scheduleColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			schedule.ID, schedule.Name, schedule.Enabled, encodeChecks(schedule.Checks), schedule.AllHosts, encodeChecks(schedule.HostIDs),
			encodeDays(schedule.Days), schedule.Time, schedule.Timezone, schedule.NextRunAt, schedule.LastRunAt, schedule.CreatedAt, schedule.CreatedBy)
	} else {
		var result sql.Result
		result, err = db.Exec(`UPDATE schedules SET name = ?, enabled = ?, checks = ?, all_hosts = ?, host_ids = ?, days = ?, time = ?,
			timezone = ?, next_run_at = ? WHERE id = ?`, schedule.Name, schedule.Enabled, encodeChecks(schedule.Checks), schedule.AllHosts,
			encodeChecks(schedule.HostIDs), encodeDays(schedule.Days), schedule.Time, schedule.Timezone, schedule.NextRunAt, schedule.ID)
		if err == nil {
			if changed, _ := result.RowsAffected(); changed == 0 {
				return Schedule{}, ErrScheduleNotFound
			}
		}
	}
	if err != nil {
		return Schedule{}, err
	}
	return GetSchedule(schedule.ID)
}

// DeleteSchedule removes a schedule and returns it.
func DeleteSchedule(id string) (Schedule, error) {
	schedule, err := GetSchedule(id)
	if err != nil {
		return Schedule{}, err
	}
	db, err := database()
	if err != nil {
		return Schedule{}, err
	}
	_, err = db.Exec("DELETE FROM schedules WHERE id = ?", id)
	return schedule, err
}

// DueSchedules lists enabled schedules whose next run is at or before now,
// including runs missed while the server was stopped.
func DueSchedules(now time.Time) ([]Schedule, error) {
	schedules, err := Schedules()
	if err != nil {
		return nil, err
	}
	due := make([]Schedule, 0)
	for _, schedule := range schedules {
		next, err := time.Parse(time.RFC3339, schedule.NextRunAt)
		if schedule.Enabled && err == nil && !next.After(now) {
			due = append(due, schedule)
		}
	}
	return due, nil
}

// ScheduleRan records a run at ranAt and the next one.
func ScheduleRan(id string, ranAt time.Time, next string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE schedules SET last_run_at = ?, next_run_at = ? WHERE id = ?", ranAt.UTC().Format(time.RFC3339), next, id)
	return err
}

// Covers reports whether the schedule scans host.
func (schedule Schedule) Covers(hostID string) bool {
	if schedule.AllHosts {
		return true
	}
	for _, id := range schedule.HostIDs {
		if id == hostID {
			return true
		}
	}
	return false
}

// NextScan is a host's next scheduled scan.
type NextScan struct {
	ScheduleID string `json:"schedule_id"`
	Schedule   string `json:"schedule"`
	At         string `json:"at"`
}

// nextScans returns each host's earliest scheduled scan.
func nextScans(hosts []Host) (map[string]NextScan, error) {
	schedules, err := Schedules()
	if err != nil {
		return nil, err
	}
	result := make(map[string]NextScan)
	for _, schedule := range schedules {
		if !schedule.Enabled || schedule.NextRunAt == "" {
			continue
		}
		for _, host := range hosts {
			if !schedule.Covers(host.ID) {
				continue
			}
			if current, ok := result[host.ID]; !ok || strings.Compare(schedule.NextRunAt, current.At) < 0 {
				result[host.ID] = NextScan{ScheduleID: schedule.ID, Schedule: schedule.Name, At: schedule.NextRunAt}
			}
		}
	}
	return result, nil
}
