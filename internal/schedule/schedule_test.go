package schedule

import (
	"testing"
	"time"
)

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestNext(t *testing.T) {
	daily := When{Days: []int{0, 1, 2, 3, 4, 5, 6}, Time: "02:30", Timezone: "Europe/Stockholm"}
	for _, test := range []struct {
		name  string
		when  When
		after string
		want  string
	}{
		{"later today", daily, "2026-10-10T00:00:00Z", "2026-10-10T00:30:00Z"},
		{"exactly at the time runs the next day", daily, "2026-10-11T00:30:00Z", "2026-10-12T00:30:00Z"},
		{"weekdays skip the weekend", When{Days: []int{1, 2, 3, 4, 5}, Time: "09:00", Timezone: "UTC"}, "2026-10-09T10:00:00Z", "2026-10-12T09:00:00Z"},
		{"weekly", When{Days: []int{0}, Time: "03:00", Timezone: "UTC"}, "2026-10-11T03:00:00Z", "2026-10-18T03:00:00Z"},
		// 02:30 does not exist on 29 March 2026 in Stockholm; it runs at 03:30.
		{"daylight saving starts", daily, "2026-03-28T23:00:00Z", "2026-03-29T01:30:00Z"},
	} {
		got, err := test.when.Next(at(t, test.after))
		if err != nil || !got.Equal(at(t, test.want)) {
			t.Errorf("%s: Next() = %s, %v; want %s", test.name, got.Format(time.RFC3339), err, test.want)
		}
	}
}

// Stockholm moves from summer time (UTC+2) to winter time (UTC+1) at 01:00
// UTC on 25 October 2026, so 02:30 happens twice that morning. Go does not
// promise which one a time means; what matters is one run that day.
func TestDaylightSavingEndsRunsOnce(t *testing.T) {
	daily := When{Days: []int{0, 1, 2, 3, 4, 5, 6}, Time: "02:30", Timezone: "Europe/Stockholm"}
	first, err := daily.Next(at(t, "2026-10-24T23:00:00Z"))
	if err != nil || (!first.Equal(at(t, "2026-10-25T00:30:00Z")) && !first.Equal(at(t, "2026-10-25T01:30:00Z"))) {
		t.Fatalf("first = %s, %v", first, err)
	}
	second, err := daily.Next(first)
	if err != nil || !second.Equal(at(t, "2026-10-26T01:30:00Z")) {
		t.Fatalf("after %s, next = %s, %v; want 2026-10-26T01:30:00Z", first, second, err)
	}
}

func TestValidate(t *testing.T) {
	for name, when := range map[string]When{
		"no days":      {Time: "02:30", Timezone: "UTC"},
		"bad day":      {Days: []int{7}, Time: "02:30", Timezone: "UTC"},
		"repeated day": {Days: []int{1, 1}, Time: "02:30", Timezone: "UTC"},
		"bad time":     {Days: []int{1}, Time: "2:30", Timezone: "UTC"},
		"24:00":        {Days: []int{1}, Time: "24:00", Timezone: "UTC"},
		"no zone":      {Days: []int{1}, Time: "02:30"},
		"bad zone":     {Days: []int{1}, Time: "02:30", Timezone: "Mars/Olympus"},
	} {
		if when.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDescribe(t *testing.T) {
	for want, when := range map[string]When{
		"Every day at 02:30 (UTC)":               {Days: []int{0, 1, 2, 3, 4, 5, 6}, Time: "02:30", Timezone: "UTC"},
		"Every weekday at 09:00 (UTC)":           {Days: []int{5, 1, 2, 3, 4}, Time: "09:00", Timezone: "UTC"},
		"Every Sunday, Wednesday at 03:00 (UTC)": {Days: []int{3, 0}, Time: "03:00", Timezone: "UTC"},
	} {
		if got := when.Describe(); got != want {
			t.Errorf("Describe() = %q, want %q", got, want)
		}
	}
}

func TestTheRepeatedHourDoesNotRunTwice(t *testing.T) {
	daily := When{Days: []int{0, 1, 2, 3, 4, 5, 6}, Time: "02:30", Timezone: "Europe/Stockholm"}
	// 00:30 UTC is the first 02:30 (summer time) on 25 October 2026.
	next, err := daily.Next(at(t, "2026-10-25T00:30:00Z"))
	if err != nil || !next.Equal(at(t, "2026-10-26T01:30:00Z")) {
		t.Fatalf("after the first 02:30, next = %s, %v; want the next day", next, err)
	}
}
