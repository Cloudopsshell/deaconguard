// Package schedule works out when a scheduled scan runs next: on chosen days
// of the week, at a time of day, in a time zone, through daylight saving
// changes.
package schedule

import (
	"errors"
	"fmt"
	"strings"
	"time"

	// The server may run where the system has no time zone database.
	_ "time/tzdata"
)

// When is when a schedule runs.
type When struct {
	// Days are the days of the week it runs on, Sunday being 0.
	Days []int
	// Time is the time of day, such as 02:30.
	Time string
	// Timezone is an IANA time zone, such as Europe/Stockholm or UTC.
	Timezone string
}

// Validate reports the first problem with when, in words for the dashboard.
func (when When) Validate() error {
	if len(when.Days) == 0 {
		return errors.New("choose at least one day")
	}
	seen := map[int]bool{}
	for _, day := range when.Days {
		if day < 0 || day > 6 || seen[day] {
			return fmt.Errorf("days must be distinct numbers from 0 (Sunday) to 6 (Saturday)")
		}
		seen[day] = true
	}
	if _, _, err := clock(when.Time); err != nil {
		return err
	}
	if _, err := location(when.Timezone); err != nil {
		return err
	}
	return nil
}

// Next returns the first run strictly after after.
func (when When) Next(after time.Time) (time.Time, error) {
	if err := when.Validate(); err != nil {
		return time.Time{}, err
	}
	hour, minute, _ := clock(when.Time)
	zone, _ := location(when.Timezone)
	days := map[time.Weekday]bool{}
	for _, day := range when.Days {
		days[time.Weekday(day)] = true
	}
	local := after.In(zone)
	// Eight days always reach the next chosen day, after today's time.
	for offset := 0; offset <= 8; offset++ {
		day := local.AddDate(0, 0, offset)
		// A time skipped by a daylight saving change runs an hour later.
		candidate := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, zone)
		if !days[candidate.Weekday()] || !candidate.After(after) {
			continue
		}
		// When the clock goes back, the time happens twice; once its first
		// occurrence has passed, the day has had its run.
		if offset == 0 && local.Hour()*60+local.Minute() >= hour*60+minute {
			continue
		}
		return candidate.UTC(), nil
	}
	return time.Time{}, errors.New("no next run found")
}

// Describe says when a schedule runs, such as "Every day at 02:30 (Europe/Stockholm)".
func (when When) Describe() string {
	names := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	var days string
	switch {
	case len(when.Days) == 7:
		days = "Every day"
	case len(when.Days) == 5 && !contains(when.Days, 0) && !contains(when.Days, 6):
		days = "Every weekday"
	default:
		chosen := make([]string, 0, len(when.Days))
		for day := 0; day < 7; day++ {
			if contains(when.Days, day) {
				chosen = append(chosen, names[day])
			}
		}
		days = "Every " + strings.Join(chosen, ", ")
	}
	return fmt.Sprintf("%s at %s (%s)", days, when.Time, when.Timezone)
}

func contains(days []int, day int) bool {
	for _, value := range days {
		if value == day {
			return true
		}
	}
	return false
}

func clock(value string) (int, int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil || len(value) != 5 {
		return 0, 0, fmt.Errorf("the time must be HH:MM on a 24-hour clock, such as 02:30")
	}
	return parsed.Hour(), parsed.Minute(), nil
}

func location(name string) (*time.Location, error) {
	if name == "" || name == "Local" {
		return nil, errors.New("choose a time zone, such as UTC or Europe/Stockholm")
	}
	zone, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("unknown time zone %q", name)
	}
	return zone, nil
}
