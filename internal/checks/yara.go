package checks

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const yaraTimeout = 45 * time.Minute

const (
	yaraDetectCommand  = "command -v yr 2>/dev/null; true"
	yaraVersionCommand = "yr --version 2>/dev/null"
	// The rules arrive on standard input and go to a private temporary
	// directory, because yr reads rules only from a file. Its path is printed
	// first so its own matches against the rules can be dropped: /tmp is one
	// of the scanned directories. YARA-X scans the directories ClamAV does, at
	// the lowest CPU priority, skipping files over 50 MB and giving up on a
	// file after 30 seconds. Missing directories are skipped.
	yaraScanCommand = `rules=$(mktemp -d) || exit 3; trap 'rm -rf "$rules"' EXIT; ` +
		`cat > "$rules/rules.yar" || exit 3; printf 'rules-directory %s\n' "$rules"; ` +
		`for d in /tmp /var/tmp /dev/shm /home /root /opt /usr/local /var/www /srv; do [ -d "$d" ] || continue; ` +
		`nice -n 19 yr scan --recursive --output-format ndjson --print-meta --disable-console-logs --disable-warnings ` +
		`--skip-larger 52428800 --timeout 30 --threads 2 "$rules/rules.yar" "$d" 2>/dev/null; done; true`
)

// YARAInput is the rule set an advanced scan runs: its text, and a version
// such as "YARA Forge core 2026-10-04" for the report.
type YARAInput struct {
	Rules   []byte
	Version string
	// Unavailable explains why there are no rules, for the report.
	Unavailable string
}

// yaraMatch is one line of `yr scan --output-format ndjson --print-meta`.
type yaraMatch struct {
	Path  string `json:"path"`
	Rules []struct {
		Identifier string  `json:"identifier"`
		Meta       [][]any `json:"meta"`
	} `json:"rules"`
}

func runYARA(executor *Executor, input YARAInput) Result {
	if len(input.Rules) == 0 {
		reason := input.Unavailable
		if reason == "" {
			reason = "no rules were provided"
		}
		return Result{
			Status: StatusSkipped, Summary: "YARA rules are not available",
			Notes:    []string{"The advanced scan needs the YARA Forge rules, which could not be loaded (" + truncate(reason, 200) + "). It was not run, so its absence of findings means nothing."},
			Findings: []Finding{},
		}
	}
	output, _, err := executor.Run(yaraDetectCommand, 4096, time.Minute)
	if err != nil {
		return failed(fmt.Errorf("look for YARA-X: %w", err))
	}
	if strings.TrimSpace(string(output)) == "" {
		return Result{
			Status: StatusSkipped, Summary: "YARA-X is not installed on this host",
			Notes:    []string{"The advanced scan uses YARA-X (yr), which the DeaconGuard install script installs. Run the install script again to add it: curl -fsSL https://get.deaconguard.io | sudo sh -"},
			Findings: []Finding{},
		}
	}
	var result Result
	if version, _, err := executor.Run(yaraVersionCommand, 4096, time.Minute); err == nil {
		result.note("Engine: %s. Rules: %s.", strings.TrimSpace(string(version)), input.Version)
	}
	output, code, privileged, err := executor.RunPrivilegedInput(yaraScanCommand, input.Rules, 8<<20, yaraTimeout)
	if err != nil && code != 0 {
		return failed(fmt.Errorf("YARA-X scan: %w", err))
	}
	rulesDirectory := ""
	for _, line := range lines(output) {
		if directory, found := strings.CutPrefix(line, "rules-directory "); found {
			rulesDirectory = strings.TrimSpace(directory) + "/"
			continue
		}
		var match yaraMatch
		if json.Unmarshal([]byte(line), &match) != nil || match.Path == "" {
			continue
		}
		if rulesDirectory != "" && strings.HasPrefix(match.Path, rulesDirectory) {
			continue
		}
		for _, rule := range match.Rules {
			result.add(yaraFinding(match.Path, rule.Identifier, rule.Meta))
		}
	}
	if !privileged {
		result.note("Without sudo, files that belong to other users and /root were not scanned.")
	}
	result.Privileged = privileged
	return result.finish(!privileged)
}

// yaraFinding turns a rule match into a finding. Rules state how confident
// their authors are as a score from 0 to 100; YARA matches patterns, so even
// a high score is reported below ClamAV's exact signature matches.
func yaraFinding(path, identifier string, meta [][]any) Finding {
	values := map[string]string{}
	for _, pair := range meta {
		if len(pair) != 2 {
			continue
		}
		key, ok := pair[0].(string)
		if !ok {
			continue
		}
		if _, seen := values[key]; seen {
			continue
		}
		switch value := pair[1].(type) {
		case string:
			values[key] = value
		case float64:
			values[key] = strconv.FormatFloat(value, 'f', -1, 64)
		}
	}
	score, _ := strconv.Atoi(values["score"])
	severity := "LOW"
	switch {
	case score >= 90:
		severity = "CRITICAL"
	case score >= 75:
		severity = "HIGH"
	case score >= 60:
		severity = "MEDIUM"
	}
	title := values["description"]
	if title == "" {
		title = identifier
	}
	detail := "YARA rule " + identifier + " matched this file"
	if values["author"] != "" {
		detail += " (rule by " + values["author"] + ")"
	}
	detail += ". YARA rules describe how malicious files look, so a match is a strong lead but can be a false positive: " +
		"look at the file before acting, and isolate the host if it is malicious."
	if values["reference"] != "" && strings.HasPrefix(values["reference"], "http") {
		detail += " Reference: " + values["reference"]
	}
	return Finding{
		Rule: "yara." + identifier, Severity: severity, Title: "YARA: " + truncate(title, 160),
		Detail: detail, Evidence: path,
	}
}
