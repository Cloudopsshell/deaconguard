package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// RegistryLogin is a saved login for one container registry. Secret is a
// password or access token; the server never sends it back to the dashboard.
type RegistryLogin struct {
	ID string `json:"id"`
	// Registry is the registry's host, with its port if it has one, as
	// images.RegistryHost names it: "registry-1.docker.io" for Docker Hub.
	Registry  string `json:"registry"`
	Username  string `json:"username"`
	Secret    string `json:"-"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Image is an image in a registry that DeaconGuard checks, by reference and
// platform. Latest is its most recent scan, if it has one.
type Image struct {
	ID        string     `json:"id"`
	Reference string     `json:"reference"`
	Platform  string     `json:"platform"`
	CreatedBy string     `json:"created_by"`
	CreatedAt string     `json:"created_at"`
	Latest    *ImageScan `json:"latest,omitempty"`
}

// ImageScan is one check of an image. Only a succeeded scan has a digest and
// a result; Result is the checked image as JSON, a checks.ContainerResult.
type ImageScan struct {
	ID         string          `json:"id"`
	ImageID    string          `json:"image_id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	Digest     string          `json:"digest,omitempty"`
	OS         string          `json:"os,omitempty"`
	Severity   SeverityCounts  `json:"severity"`
	Exploited  int             `json:"exploited"`
	Fixable    int             `json:"fixable"`
	Result     json.RawMessage `json:"result,omitempty"`
	StartedBy  string          `json:"started_by"`
	StartedAt  string          `json:"started_at"`
	FinishedAt string          `json:"finished_at,omitempty"`
}

// keptImageScans is how many scans of each image are kept.
const keptImageScans = 20

var (
	ErrRegistryLoginNotFound = errors.New("unknown registry login")
	ErrRegistryLoginExists   = errors.New("this registry already has a login; edit that one")
	ErrImageNotFound         = errors.New("unknown image")
	ErrImageExists           = errors.New("this image is already in the list for that platform")
	ErrImageScanNotFound     = errors.New("unknown image scan")
	ErrImageScanInProgress   = errors.New("a scan of this image is already queued or running")
)

const registryLoginColumns = "id, registry, username, secret, created_by, created_at, updated_at"

func scanRegistryLogin(row rowScanner) (RegistryLogin, error) {
	var login RegistryLogin
	err := row.Scan(&login.ID, &login.Registry, &login.Username, &login.Secret, &login.CreatedBy, &login.CreatedAt, &login.UpdatedAt)
	return login, err
}

// RegistryLogins lists the saved registry logins by registry.
func RegistryLogins() ([]RegistryLogin, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + registryLoginColumns + " FROM registry_logins ORDER BY registry")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logins := make([]RegistryLogin, 0)
	for rows.Next() {
		login, err := scanRegistryLogin(rows)
		if err != nil {
			return nil, err
		}
		logins = append(logins, login)
	}
	return logins, rows.Err()
}

// GetRegistryLogin returns one saved login.
func GetRegistryLogin(id string) (RegistryLogin, error) {
	db, err := database()
	if err != nil {
		return RegistryLogin{}, err
	}
	login, err := scanRegistryLogin(db.QueryRow("SELECT "+registryLoginColumns+" FROM registry_logins WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return RegistryLogin{}, ErrRegistryLoginNotFound
	}
	return login, err
}

// RegistryLoginFor returns the saved login for a registry host, if there is one.
func RegistryLoginFor(registry string) (RegistryLogin, bool, error) {
	db, err := database()
	if err != nil {
		return RegistryLogin{}, false, err
	}
	login, err := scanRegistryLogin(db.QueryRow("SELECT "+registryLoginColumns+" FROM registry_logins WHERE registry = ?", registry))
	if errors.Is(err, sql.ErrNoRows) {
		return RegistryLogin{}, false, nil
	}
	return login, err == nil, err
}

// SaveRegistryLogin adds a login without an ID, or replaces the one with its
// ID, and returns it as stored. An empty Secret on an existing login keeps
// the saved one.
func SaveRegistryLogin(login RegistryLogin) (RegistryLogin, error) {
	db, err := database()
	if err != nil {
		return RegistryLogin{}, err
	}
	now := nowText()
	if login.ID == "" {
		if login.ID, err = newID(); err != nil {
			return RegistryLogin{}, err
		}
		_, err = db.Exec("INSERT INTO registry_logins ("+registryLoginColumns+") VALUES (?, ?, ?, ?, ?, ?, ?)",
			login.ID, login.Registry, login.Username, login.Secret, login.CreatedBy, now, now)
	} else {
		var result sql.Result
		result, err = db.Exec(`UPDATE registry_logins SET registry = ?, username = ?, secret = CASE WHEN ? = '' THEN secret ELSE ? END,
			updated_at = ? WHERE id = ?`, login.Registry, login.Username, login.Secret, login.Secret, now, login.ID)
		if err == nil {
			if changed, _ := result.RowsAffected(); changed == 0 {
				return RegistryLogin{}, ErrRegistryLoginNotFound
			}
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return RegistryLogin{}, ErrRegistryLoginExists
		}
		return RegistryLogin{}, err
	}
	return GetRegistryLogin(login.ID)
}

// DeleteRegistryLogin removes a saved login and returns it.
func DeleteRegistryLogin(id string) (RegistryLogin, error) {
	login, err := GetRegistryLogin(id)
	if err != nil {
		return RegistryLogin{}, err
	}
	db, err := database()
	if err != nil {
		return RegistryLogin{}, err
	}
	_, err = db.Exec("DELETE FROM registry_logins WHERE id = ?", id)
	return login, err
}

const imageColumns = "id, reference, platform, created_by, created_at"

func scanImage(row rowScanner) (Image, error) {
	var image Image
	err := row.Scan(&image.ID, &image.Reference, &image.Platform, &image.CreatedBy, &image.CreatedAt)
	return image, err
}

// Images lists the images by reference, each with its latest scan.
func Images() ([]Image, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT " + imageColumns + " FROM images ORDER BY reference, platform")
	if err != nil {
		return nil, err
	}
	list := make([]Image, 0)
	for rows.Next() {
		image, err := scanImage(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, image)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for index := range list {
		if list[index].Latest, err = latestImageScan(db, list[index].ID); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// GetImage returns one image with its latest scan.
func GetImage(id string) (Image, error) {
	db, err := database()
	if err != nil {
		return Image{}, err
	}
	image, err := scanImage(db.QueryRow("SELECT "+imageColumns+" FROM images WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Image{}, ErrImageNotFound
	}
	if err != nil {
		return Image{}, err
	}
	image.Latest, err = latestImageScan(db, id)
	return image, err
}

// AddImage adds an image to check.
func AddImage(reference, platform, createdBy string) (Image, error) {
	db, err := database()
	if err != nil {
		return Image{}, err
	}
	id, err := newID()
	if err != nil {
		return Image{}, err
	}
	_, err = db.Exec("INSERT INTO images ("+imageColumns+") VALUES (?, ?, ?, ?, ?)", id, reference, platform, createdBy, nowText())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Image{}, ErrImageExists
		}
		return Image{}, err
	}
	return GetImage(id)
}

// DeleteImage removes an image and its scans, and returns it.
func DeleteImage(id string) (Image, error) {
	image, err := GetImage(id)
	if err != nil {
		return Image{}, err
	}
	db, err := database()
	if err != nil {
		return Image{}, err
	}
	_, err = db.Exec("DELETE FROM images WHERE id = ?", id)
	return image, err
}

// imageScanSummary leaves out the result, which can be large.
const imageScanSummary = `id, image_id, status, error, digest, os, critical, high, medium, low, unknown, exploited, fixable,
	started_by, started_at, finished_at`

func scanImageScan(row rowScanner, withResult bool) (ImageScan, error) {
	var scan ImageScan
	var result string
	fields := []any{&scan.ID, &scan.ImageID, &scan.Status, &scan.Error, &scan.Digest, &scan.OS,
		&scan.Severity.Critical, &scan.Severity.High, &scan.Severity.Medium, &scan.Severity.Low, &scan.Severity.Unknown,
		&scan.Exploited, &scan.Fixable, &scan.StartedBy, &scan.StartedAt, &scan.FinishedAt}
	if withResult {
		fields = append(fields, &result)
	}
	if err := row.Scan(fields...); err != nil {
		return ImageScan{}, err
	}
	if result != "" {
		scan.Result = json.RawMessage(result)
	}
	return scan, nil
}

func latestImageScan(db *sql.DB, imageID string) (*ImageScan, error) {
	scan, err := scanImageScan(db.QueryRow("SELECT "+imageScanSummary+" FROM image_scans WHERE image_id = ? ORDER BY started_at DESC, rowid DESC LIMIT 1", imageID), false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

// ImageScans lists an image's scans, newest first, without their results.
func ImageScans(imageID string) ([]ImageScan, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("SELECT "+imageScanSummary+" FROM image_scans WHERE image_id = ? ORDER BY started_at DESC, rowid DESC", imageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := make([]ImageScan, 0)
	for rows.Next() {
		scan, err := scanImageScan(rows, false)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

// GetImageScan returns one scan with its result.
func GetImageScan(id string) (ImageScan, error) {
	db, err := database()
	if err != nil {
		return ImageScan{}, err
	}
	scan, err := scanImageScan(db.QueryRow("SELECT "+imageScanSummary+", result FROM image_scans WHERE id = ?", id), true)
	if errors.Is(err, sql.ErrNoRows) {
		return ImageScan{}, ErrImageScanNotFound
	}
	return scan, err
}

// QueueImageScan queues a scan of an image, unless one is already queued or
// running.
func QueueImageScan(imageID, startedBy string) (ImageScan, error) {
	db, err := database()
	if err != nil {
		return ImageScan{}, err
	}
	id, err := newID()
	if err != nil {
		return ImageScan{}, err
	}
	result, err := db.Exec(`INSERT INTO image_scans (id, image_id, status, started_by, started_at)
		SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM image_scans WHERE image_id = ? AND status IN ('queued', 'running'))`,
		id, imageID, ScanQueued, startedBy, nowText(), imageID)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return ImageScan{}, ErrImageNotFound
		}
		return ImageScan{}, err
	}
	if added, _ := result.RowsAffected(); added == 0 {
		return ImageScan{}, ErrImageScanInProgress
	}
	return GetImageScan(id)
}

// NextImageScan marks the oldest queued scan running and returns it.
func NextImageScan() (ImageScan, bool, error) {
	db, err := database()
	if err != nil {
		return ImageScan{}, false, err
	}
	for {
		scan, err := scanImageScan(db.QueryRow("SELECT "+imageScanSummary+" FROM image_scans WHERE status = ? ORDER BY started_at, rowid LIMIT 1", ScanQueued), false)
		if errors.Is(err, sql.ErrNoRows) {
			return ImageScan{}, false, nil
		}
		if err != nil {
			return ImageScan{}, false, err
		}
		result, err := db.Exec("UPDATE image_scans SET status = ? WHERE id = ? AND status = ?", ScanRunning, scan.ID, ScanQueued)
		if err != nil {
			return ImageScan{}, false, err
		}
		if claimed, _ := result.RowsAffected(); claimed == 1 {
			scan.Status = ScanRunning
			return scan, true, nil
		}
	}
}

// FinishImageScan saves a succeeded scan's result, and keeps only the image's
// newest scans.
func FinishImageScan(scan ImageScan) error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE image_scans SET status = ?, digest = ?, os = ?, critical = ?, high = ?, medium = ?, low = ?, unknown = ?,
		exploited = ?, fixable = ?, result = ?, finished_at = ? WHERE id = ?`,
		ScanSucceeded, scan.Digest, scan.OS, scan.Severity.Critical, scan.Severity.High, scan.Severity.Medium, scan.Severity.Low,
		scan.Severity.Unknown, scan.Exploited, scan.Fixable, string(scan.Result), nowText(), scan.ID)
	if err != nil {
		return err
	}
	return pruneImageScans(db, scan.ImageID)
}

// FailImageScan records why a scan failed.
func FailImageScan(id, message string) error {
	db, err := database()
	if err != nil {
		return err
	}
	var imageID string
	if err := db.QueryRow("SELECT image_id FROM image_scans WHERE id = ?", id).Scan(&imageID); err != nil {
		return err
	}
	if _, err := db.Exec("UPDATE image_scans SET status = ?, error = ?, finished_at = ? WHERE id = ?", ScanFailed, message, nowText(), id); err != nil {
		return err
	}
	return pruneImageScans(db, imageID)
}

// InterruptImageScans fails the scans that were running when the server
// stopped; queued ones still run.
func InterruptImageScans() error {
	db, err := database()
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE image_scans SET status = ?, error = ?, finished_at = ? WHERE status = ?",
		ScanFailed, "The server stopped during this scan. Scan again.", nowText(), ScanRunning)
	return err
}

func pruneImageScans(db *sql.DB, imageID string) error {
	_, err := db.Exec(`DELETE FROM image_scans WHERE image_id = ? AND status NOT IN ('queued', 'running') AND id NOT IN (
		SELECT id FROM image_scans WHERE image_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?)`, imageID, imageID, keptImageScans)
	return err
}
