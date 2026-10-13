package store

import (
	"encoding/json"
	"errors"
	"time"
)

// SLA is how many days a vulnerability may stay unfixed on a host, counted
// from the scan that first found it there: by severity, and for those known
// to be exploited, whichever is sooner.
type SLA struct {
	Enabled   bool `json:"enabled"`
	Exploited int  `json:"exploited"`
	Critical  int  `json:"critical"`
	High      int  `json:"high"`
	Medium    int  `json:"medium"`
	Low       int  `json:"low"`
}

// DefaultSLA follows common practice: CISA gives US agencies 14 days for
// known exploited vulnerabilities, and 15 for critical ones on the internet.
var DefaultSLA = SLA{Enabled: true, Exploited: 14, Critical: 15, High: 30, Medium: 90, Low: 180}

const metaSLA = "sla"

// GetSLA returns the fix deadlines, DefaultSLA until an admin changes them.
func GetSLA() (SLA, error) {
	value, err := Meta(metaSLA)
	if err != nil || value == "" {
		return DefaultSLA, err
	}
	sla := DefaultSLA
	if err := json.Unmarshal([]byte(value), &sla); err != nil {
		return DefaultSLA, nil
	}
	return sla, nil
}

// SetSLA saves the fix deadlines.
func SetSLA(sla SLA) error {
	for _, days := range []int{sla.Exploited, sla.Critical, sla.High, sla.Medium, sla.Low} {
		if days < 1 || days > 730 {
			return errors.New("each deadline is 1 to 730 days")
		}
	}
	encoded, err := json.Marshal(sla)
	if err != nil {
		return err
	}
	return SetMeta(metaSLA, string(encoded))
}

// Days is the deadline, in days, for a vulnerability of severity, known to
// be exploited or not; 0 when SLAs are off or the severity has none.
func (sla SLA) Days(severity string, exploited bool) int {
	if !sla.Enabled {
		return 0
	}
	days := map[string]int{"CRITICAL": sla.Critical, "HIGH": sla.High, "MEDIUM": sla.Medium, "LOW": sla.Low}[severity]
	if exploited && (days == 0 || sla.Exploited < days) {
		days = sla.Exploited
	}
	return days
}

// due fills in an affected package's deadline from when its host first had
// the CVE. Overdue is only set when an update or a restart fixes it: one
// waiting on the distribution can't be fixed yet.
func (sla SLA) due(item *AffectedPackage, now time.Time) {
	days := sla.Days(item.Severity, item.KEV)
	first, err := time.Parse(time.RFC3339, item.FirstSeen)
	if days == 0 || err != nil {
		return
	}
	due := first.Add(time.Duration(days) * 24 * time.Hour)
	item.DueAt = due.UTC().Format(time.RFC3339)
	item.Overdue = actionableFix(item.Fix) && now.After(due)
}
