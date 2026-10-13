package store

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxTags is how many tags a host can have.
const MaxTags = 20

var tagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,39}$`)

// ErrInvalidTag explains what a tag may look like.
var ErrInvalidTag = errors.New("a tag is 1 to 40 lower-case letters, digits and . _ : / -, starting with a letter or digit, such as prod or team:web")

// NormalizeTags lower-cases, trims, sorts and de-duplicates tags, and checks
// each one.
func NormalizeTags(tags []string) ([]string, error) {
	seen := make(map[string]bool, len(tags))
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || seen[tag] {
			continue
		}
		if !tagPattern.MatchString(tag) {
			return nil, fmt.Errorf("%q: %w", tag, ErrInvalidTag)
		}
		seen[tag] = true
		result = append(result, tag)
	}
	if len(result) > MaxTags {
		return nil, fmt.Errorf("a host can have up to %d tags", MaxTags)
	}
	sort.Strings(result)
	return result, nil
}

// SetHostTags replaces a host's tags.
func SetHostTags(hostID string, tags []string) ([]string, error) {
	tags, err := NormalizeTags(tags)
	if err != nil {
		return nil, err
	}
	if _, err := GetHost(hostID); err != nil {
		return nil, err
	}
	db, err := database()
	if err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM host_tags WHERE host_id = ?", hostID); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if _, err := tx.Exec("INSERT INTO host_tags (host_id, tag) VALUES (?, ?)", hostID, tag); err != nil {
			return nil, err
		}
	}
	return tags, tx.Commit()
}

// hostTags returns every host's tags, sorted.
func hostTags() (map[string][]string, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT host_id, tag FROM host_tags ORDER BY host_id, tag")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tags := make(map[string][]string)
	for rows.Next() {
		var hostID, tag string
		if err := rows.Scan(&hostID, &tag); err != nil {
			return nil, err
		}
		tags[hostID] = append(tags[hostID], tag)
	}
	return tags, rows.Err()
}

// TagCount is a tag and how many hosts have it.
type TagCount struct {
	Tag   string `json:"tag"`
	Hosts int    `json:"hosts"`
}

// Tags lists the tags in use, by name.
func Tags() ([]TagCount, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT tag, COUNT(*) FROM host_tags GROUP BY tag ORDER BY tag")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TagCount, 0)
	for rows.Next() {
		var item TagCount
		if err := rows.Scan(&item.Tag, &item.Hosts); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// TrendPoint is the vulnerabilities on the hosts on one day: each host's
// counts from its last scan that checked packages on or before that day.
type TrendPoint struct {
	Day       string `json:"day"`
	Hosts     int    `json:"hosts"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
	Medium    int    `json:"medium"`
	Low       int    `json:"low"`
	Unknown   int    `json:"unknown"`
	Exploited int    `json:"exploited"`
	Likely    int    `json:"likely"`
}

// TrendFilter limits a trend to one host, or to the hosts with a tag.
type TrendFilter struct {
	HostID string
	Tag    string
}

// MaxTrendDays is the longest trend.
const MaxTrendDays = 365

// Trends returns one point a day for the days up to and including today.
func Trends(days int, filter TrendFilter, now time.Time) ([]TrendPoint, error) {
	if days < 1 || days > MaxTrendDays {
		return nil, fmt.Errorf("a trend covers 1 to %d days", MaxTrendDays)
	}
	db, err := database()
	if err != nil {
		return nil, err
	}
	end := now.UTC().Truncate(24 * time.Hour)
	start := end.AddDate(0, 0, -(days - 1))
	query := `SELECT t.host_id, t.day, t.critical, t.high, t.medium, t.low, t.unknown, t.exploited, t.likely
		FROM host_trends t WHERE t.day <= ?`
	arguments := []any{end.Format(time.DateOnly)}
	if filter.HostID != "" {
		query += " AND t.host_id = ?"
		arguments = append(arguments, filter.HostID)
	}
	if filter.Tag != "" {
		query += " AND t.host_id IN (SELECT host_id FROM host_tags WHERE tag = ?)"
		arguments = append(arguments, filter.Tag)
	}
	rows, err := db.Query(query+" ORDER BY t.day", arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type entry struct {
		hostID, day string
		counts      TrendPoint
	}
	var entries []entry
	for rows.Next() {
		var item entry
		if err := rows.Scan(&item.hostID, &item.day, &item.counts.Critical, &item.counts.High, &item.counts.Medium,
			&item.counts.Low, &item.counts.Unknown, &item.counts.Exploited, &item.counts.Likely); err != nil {
			return nil, err
		}
		entries = append(entries, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Walk the days, carrying each host's latest counts forward.
	latest := make(map[string]TrendPoint)
	points := make([]TrendPoint, 0, days)
	next := 0
	for day := start; !day.After(end); day = day.AddDate(0, 0, 1) {
		text := day.Format(time.DateOnly)
		for next < len(entries) && entries[next].day <= text {
			latest[entries[next].hostID] = entries[next].counts
			next++
		}
		point := TrendPoint{Day: text, Hosts: len(latest)}
		for _, counts := range latest {
			point.Critical += counts.Critical
			point.High += counts.High
			point.Medium += counts.Medium
			point.Low += counts.Low
			point.Unknown += counts.Unknown
			point.Exploited += counts.Exploited
			point.Likely += counts.Likely
		}
		points = append(points, point)
	}
	return points, nil
}
