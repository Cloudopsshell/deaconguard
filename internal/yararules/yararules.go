// Package yararules provides the rules of the advanced antivirus scan: the
// "core" package of YARA Forge (https://github.com/YARAHQ/yara-forge), a
// weekly, tested collection of public YARA rules chosen for few false
// positives. It is downloaded and cached like the advisory feeds, and never
// shipped with DeaconGuard, whose license differs from the rules'.
package yararules

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"deaconguard/internal/advisory"
	"deaconguard/internal/checks"
)

// Source is the latest YARA Forge core package; GitHub redirects to the
// newest weekly release.
const Source = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"

// maxRules bounds the extracted rule file; the core package is about 8 MB.
const maxRules = 64 << 20

// header starts every YARA Forge rule package.
const header = "YARA-Forge YARA Rule Package"

// Load returns the cached rules, downloading a newer package every 12 hours
// and keeping the last good one when the download fails.
func Load(client advisory.HTTPClient, now time.Time) (checks.YARAInput, error) {
	feed, err := advisory.LoadFeed(Source, "yara-forge-core", client, now)
	if err != nil {
		return checks.YARAInput{}, fmt.Errorf("download the YARA Forge rules: %w", err)
	}
	input, err := Extract(feed.Data)
	if err != nil {
		return checks.YARAInput{}, err
	}
	if feed.Metadata.Stale {
		input.Version += fmt.Sprintf(" (could not be refreshed; %.0f hours old)", feed.Metadata.AgeHours)
	}
	return input, nil
}

// Provider returns a function for scan.Options.YARARules that loads the rules
// and turns a failure into the reason the report gives.
func Provider() func() checks.YARAInput {
	return func() checks.YARAInput {
		input, err := Load(nil, time.Now().UTC())
		if err != nil {
			return checks.YARAInput{Unavailable: err.Error()}
		}
		return input
	}
}

// Extract returns the rule file from a YARA Forge rule package.
func Extract(archive []byte) (checks.YARAInput, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return checks.YARAInput{}, fmt.Errorf("read the YARA Forge package: %w", err)
	}
	for _, file := range reader.File {
		if path.Ext(file.Name) != ".yar" {
			continue
		}
		if file.UncompressedSize64 > maxRules {
			return checks.YARAInput{}, fmt.Errorf("the YARA Forge rule file is larger than %d bytes", maxRules)
		}
		opened, err := file.Open()
		if err != nil {
			return checks.YARAInput{}, fmt.Errorf("read the YARA Forge rule file: %w", err)
		}
		rules, err := io.ReadAll(io.LimitReader(opened, maxRules+1))
		opened.Close()
		if err != nil {
			return checks.YARAInput{}, fmt.Errorf("read the YARA Forge rule file: %w", err)
		}
		return Parse(rules)
	}
	return checks.YARAInput{}, errors.New("the YARA Forge package contains no .yar rule file")
}

// Parse checks that rules are a YARA Forge rule package and reads its date.
func Parse(rules []byte) (checks.YARAInput, error) {
	if len(rules) > maxRules {
		return checks.YARAInput{}, fmt.Errorf("the YARA rules are larger than %d bytes", maxRules)
	}
	start := rules[:min(len(rules), 4096)]
	if !bytes.Contains(start, []byte(header)) || !bytes.Contains(rules, []byte("\nrule ")) {
		return checks.YARAInput{}, errors.New("the download is not a YARA Forge rule package")
	}
	version := "YARA Forge core"
	for _, line := range strings.Split(string(start), "\n") {
		if date, found := strings.CutPrefix(strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), "*")), "Creation Date:"); found {
			version += " " + strings.TrimSpace(date)
			break
		}
	}
	return checks.YARAInput{Rules: rules, Version: version}, nil
}
