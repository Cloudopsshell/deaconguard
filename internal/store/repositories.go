package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// RepositoryWatch is a repository in a registry that the server checks for
// new pushes: each image whose tag matches TagPattern (a regular expression;
// empty matches every tag) is added to the images and scanned, for the
// newest Keep matching tags. Images counts the images it added.
type RepositoryWatch struct {
	ID         string `json:"id"`
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	TagPattern string `json:"tag_pattern"`
	Platform   string `json:"platform"`
	Keep       int    `json:"keep"`
	CheckedAt  string `json:"checked_at,omitempty"`
	WatchError string `json:"watch_error,omitempty"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  string `json:"created_at"`
	Images     int    `json:"images"`
}

// RepositoryTag is a tag a repository watch has seen: what it pointed to,
// and when it was pushed (from the registry when it says, else when the
// server first saw it).
type RepositoryTag struct {
	Tag      string `json:"tag"`
	Digest   string `json:"digest"`
	PushedAt string `json:"pushed_at"`
}

var (
	ErrRepositoryWatchNotFound = errors.New("unknown repository watch")
	ErrRepositoryWatchExists   = errors.New("this repository is already watched with that tag pattern and platform")
)

const repositoryWatchColumns = "id, registry, repository, tag_pattern, platform, keep, checked_at, watch_error, created_by, created_at"

func scanRepositoryWatch(row rowScanner) (RepositoryWatch, error) {
	var watch RepositoryWatch
	err := row.Scan(&watch.ID, &watch.Registry, &watch.Repository, &watch.TagPattern, &watch.Platform, &watch.Keep,
		&watch.CheckedAt, &watch.WatchError, &watch.CreatedBy, &watch.CreatedAt)
	return watch, err
}

// AddRepositoryWatch saves a new repository watch.
func AddRepositoryWatch(watch RepositoryWatch) (RepositoryWatch, error) {
	db, err := database()
	if err != nil {
		return RepositoryWatch{}, err
	}
	if watch.ID, err = newID(); err != nil {
		return RepositoryWatch{}, err
	}
	_, err = db.Exec("INSERT INTO repository_watches (id, registry, repository, tag_pattern, platform, keep, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		watch.ID, watch.Registry, watch.Repository, watch.TagPattern, watch.Platform, watch.Keep, watch.CreatedBy, nowText())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return RepositoryWatch{}, ErrRepositoryWatchExists
		}
		return RepositoryWatch{}, err
	}
	return GetRepositoryWatch(watch.ID)
}

// RepositoryWatches lists the repository watches, each with how many images
// it added.
func RepositoryWatches() ([]RepositoryWatch, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + repositoryWatchColumns + " FROM repository_watches ORDER BY registry, repository, tag_pattern")
	if err != nil {
		return nil, err
	}
	list := make([]RepositoryWatch, 0)
	for rows.Next() {
		watch, err := scanRepositoryWatch(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, watch)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for index := range list {
		if err := db.QueryRow("SELECT COUNT(*) FROM images WHERE repository_watch_id = ?", list[index].ID).Scan(&list[index].Images); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// GetRepositoryWatch returns one repository watch.
func GetRepositoryWatch(id string) (RepositoryWatch, error) {
	db, err := database()
	if err != nil {
		return RepositoryWatch{}, err
	}
	watch, err := scanRepositoryWatch(db.QueryRow("SELECT "+repositoryWatchColumns+" FROM repository_watches WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return RepositoryWatch{}, ErrRepositoryWatchNotFound
	}
	if err != nil {
		return RepositoryWatch{}, err
	}
	err = db.QueryRow("SELECT COUNT(*) FROM images WHERE repository_watch_id = ?", id).Scan(&watch.Images)
	return watch, err
}

// UpdateRepositoryWatch changes a watch's tag pattern and how many tags it
// keeps. The tags it saw are forgotten, so its next check starts afresh.
func UpdateRepositoryWatch(id, tagPattern string, keep int) (RepositoryWatch, error) {
	db, err := database()
	if err != nil {
		return RepositoryWatch{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return RepositoryWatch{}, err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE repository_watches SET tag_pattern = ?, keep = ?, checked_at = '', watch_error = '' WHERE id = ?", tagPattern, keep, id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return RepositoryWatch{}, ErrRepositoryWatchExists
		}
		return RepositoryWatch{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return RepositoryWatch{}, ErrRepositoryWatchNotFound
	}
	if _, err := tx.Exec("DELETE FROM repository_tags WHERE watch_id = ?", id); err != nil {
		return RepositoryWatch{}, err
	}
	if err := tx.Commit(); err != nil {
		return RepositoryWatch{}, err
	}
	return GetRepositoryWatch(id)
}

// DeleteRepositoryWatch removes a watch. The images it added stay, with
// their scans, but are no longer watched.
func DeleteRepositoryWatch(id string) (RepositoryWatch, error) {
	watch, err := GetRepositoryWatch(id)
	if err != nil {
		return RepositoryWatch{}, err
	}
	db, err := database()
	if err != nil {
		return RepositoryWatch{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return RepositoryWatch{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE images SET watch = 0, repository_watch_id = '' WHERE repository_watch_id = ?", id); err != nil {
		return RepositoryWatch{}, err
	}
	if _, err := tx.Exec("DELETE FROM repository_watches WHERE id = ?", id); err != nil {
		return RepositoryWatch{}, err
	}
	return watch, tx.Commit()
}

// RepositoryWatchChecked records a check of a watch: why it failed, or ""
// when it worked.
func RepositoryWatchChecked(id, failure string, at time.Time) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE repository_watches SET watch_error = ?, checked_at = ? WHERE id = ?", failure, at.UTC().Format(time.RFC3339), id)
	return err
}

// RecheckRepositoryWatch clears a watch's failure and makes it due for a
// check at once, such as after its registry's login changed.
func RecheckRepositoryWatch(id string) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE repository_watches SET watch_error = '', checked_at = '' WHERE id = ?", id)
	return err
}

// RepositoryTags returns the tags a watch has seen, by tag.
func RepositoryTags(watchID string) (map[string]RepositoryTag, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT tag, digest, pushed_at FROM repository_tags WHERE watch_id = ?", watchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tags := make(map[string]RepositoryTag)
	for rows.Next() {
		var tag RepositoryTag
		if err := rows.Scan(&tag.Tag, &tag.Digest, &tag.PushedAt); err != nil {
			return nil, err
		}
		tags[tag.Tag] = tag
	}
	return tags, rows.Err()
}

// SaveRepositoryTags replaces the tags a watch has seen.
func SaveRepositoryTags(watchID string, tags []RepositoryTag) error {
	db, err := database()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM repository_tags WHERE watch_id = ?", watchID); err != nil {
		return err
	}
	for _, tag := range tags {
		if _, err := tx.Exec("INSERT INTO repository_tags (watch_id, tag, digest, pushed_at) VALUES (?, ?, ?, ?)", watchID, tag.Tag, tag.Digest, tag.PushedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WatchImage returns the image for a reference that a repository watch
// found, adding it, watched and linked to the watch, when it isn't listed
// yet. added says whether it was new. An image someone added by hand stays
// as it is.
func WatchImage(watchID, reference, platform, createdBy string) (image Image, added bool, err error) {
	db, err := database()
	if err != nil {
		return Image{}, false, err
	}
	image, err = scanImage(db.QueryRow("SELECT "+imageColumns+" FROM images WHERE reference = ? AND platform = ?", reference, platform))
	if err == nil {
		image.Latest, err = latestImageScan(db, image.ID)
		return image, false, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Image{}, false, err
	}
	id, err := newID()
	if err != nil {
		return Image{}, false, err
	}
	if _, err := db.Exec("INSERT INTO images (id, reference, platform, watch, created_by, created_at, repository_watch_id) VALUES (?, ?, ?, 1, ?, ?, ?)",
		id, reference, platform, createdBy, nowText(), watchID); err != nil {
		return Image{}, false, err
	}
	image, err = GetImage(id)
	return image, true, err
}

// StopWatchingOlderImages stops watching the images a repository watch
// added whose references aren't in keep, so only its newest tags are
// rescanned. Their scans stay.
func StopWatchingOlderImages(watchID string, keep map[string]bool) error {
	db, err := database()
	if err != nil {
		return err
	}
	rows, err := db.Query("SELECT id, reference FROM images WHERE repository_watch_id = ? AND watch = 1", watchID)
	if err != nil {
		return err
	}
	var stop []string
	for rows.Next() {
		var id, reference string
		if err := rows.Scan(&id, &reference); err != nil {
			rows.Close()
			return err
		}
		if !keep[reference] {
			stop = append(stop, id)
		}
	}
	rows.Close()
	for _, id := range stop {
		if _, err := db.Exec("UPDATE images SET watch = 0 WHERE id = ?", id); err != nil {
			return err
		}
	}
	return rows.Err()
}
