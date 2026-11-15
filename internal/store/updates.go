package store

import "time"

// Where the update check keeps its switch and what it last learned.
const (
	metaUpdateCheck     = "update_check"
	metaUpdateLatest    = "update_latest"
	metaUpdateCheckedAt = "update_checked_at"
	metaUpdateError     = "update_error"
)

// UpdateCheck is whether the server asks for the newest release, and what
// the last answer was.
type UpdateCheck struct {
	Enabled bool
	// Latest is the newest release last heard of, or "".
	Latest string
	// CheckedAt is when the server last asked, and Error why that failed.
	CheckedAt time.Time
	Error     string
}

// GetUpdateCheck returns the update check's switch, on unless turned off,
// and its last result.
func GetUpdateCheck() (UpdateCheck, error) {
	var check UpdateCheck
	enabled, err := Meta(metaUpdateCheck)
	if err != nil {
		return check, err
	}
	check.Enabled = enabled != "0"
	if check.Latest, err = Meta(metaUpdateLatest); err != nil {
		return check, err
	}
	if check.Error, err = Meta(metaUpdateError); err != nil {
		return check, err
	}
	at, err := Meta(metaUpdateCheckedAt)
	if err != nil {
		return check, err
	}
	check.CheckedAt, _ = time.Parse(time.RFC3339, at)
	return check, nil
}

// SetUpdateCheck turns the update check on or off. Turning it off forgets
// what it learned.
func SetUpdateCheck(on bool) error {
	if on {
		return SetMeta(metaUpdateCheck, "1")
	}
	for _, key := range []string{metaUpdateLatest, metaUpdateCheckedAt, metaUpdateError} {
		if err := SetMeta(key, ""); err != nil {
			return err
		}
	}
	return SetMeta(metaUpdateCheck, "0")
}

// RecordUpdateCheck saves the result of asking for the newest release. A
// failure keeps the release last heard of.
func RecordUpdateCheck(latest string, failure error, now time.Time) error {
	message := ""
	if failure != nil {
		message = failure.Error()
	} else if err := SetMeta(metaUpdateLatest, latest); err != nil {
		return err
	}
	if err := SetMeta(metaUpdateError, message); err != nil {
		return err
	}
	return SetMeta(metaUpdateCheckedAt, now.UTC().Format(time.RFC3339))
}
