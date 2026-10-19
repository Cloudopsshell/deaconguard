// Package iac checks the files that build and deploy containers, before
// anything is built or deployed: Dockerfiles (and Containerfiles) and
// Kubernetes manifests. The Kubernetes rules follow the Kubernetes Pod
// Security Standards (baseline and restricted) and the NSA/CISA Kubernetes
// Hardening Guide. Files are read as text; nothing is built, applied or run.
package iac

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is one problem in a file.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	// Title says what is wrong and where, such as "Deployment shop:
	// container app runs as root".
	Title string `json:"title"`
	// Detail says how to fix it.
	Detail string `json:"detail"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	// STIG are the DISA STIG rules the finding fails, such as V-242390.
	STIG []string `json:"stig,omitempty"`
}

// Result is what a scan found, and in which files.
type Result struct {
	Files    []string  `json:"files"`
	Findings []Finding `json:"findings"`
	// Notes say what couldn't be read.
	Notes []string `json:"notes,omitempty"`
}

// Rule describes a rule, for documentation and SARIF.
type Rule struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	// Source is where the rule comes from: "Pod Security Standards
	// (restricted)", "NSA/CISA Kubernetes Hardening Guide", "Docker build
	// best practices".
	Source string `json:"source"`
	// STIG are the DISA Kubernetes STIG rules it checks, such as V-242390.
	STIG []string `json:"stig,omitempty"`
}

// Rules lists every rule.
func Rules() []Rule {
	all := append(append([]Rule{}, dockerfileRules...), kubernetesRules...)
	for index := range all {
		all[index].STIG = kubernetesSTIG[all[index].ID]
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

func ruleByID(id string) Rule {
	for _, rule := range append(dockerfileRules, kubernetesRules...) {
		if rule.ID == id {
			rule.STIG = kubernetesSTIG[id]
			return rule
		}
	}
	return Rule{ID: id, Severity: "MEDIUM"}
}

// Limits.
const (
	maxFileBytes = 4 << 20
	maxFiles     = 5000
)

// skippedDirs are not walked.
var skippedDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".terraform": true}

// IsDockerfile reports whether a file name is a Dockerfile: Dockerfile,
// Containerfile, Dockerfile.prod, prod.Dockerfile.
func IsDockerfile(name string) bool {
	lower := strings.ToLower(filepath.Base(name))
	return lower == "dockerfile" || lower == "containerfile" || strings.HasPrefix(lower, "dockerfile.") ||
		strings.HasPrefix(lower, "containerfile.") || strings.HasSuffix(lower, ".dockerfile")
}

func isYAML(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

// Scan checks files and folders. "-" reads standard input as Kubernetes
// YAML, such as the output of helm template or kubectl kustomize; a file
// named as an argument is checked whatever its name.
func Scan(paths []string, stdin io.Reader) (Result, error) {
	result := Result{Files: []string{}, Findings: []Finding{}}
	check := func(name, display string, data []byte, forceKind string) {
		if bytes.IndexByte(data, 0) >= 0 {
			return // binary
		}
		result.Files = append(result.Files, display)
		kind := forceKind
		if kind == "" {
			if IsDockerfile(name) {
				kind = "dockerfile"
			} else {
				kind = "yaml"
			}
		}
		var findings []Finding
		var notes []string
		if kind == "dockerfile" {
			findings = checkDockerfile(display, string(data), dockerignoreNear(name))
		} else {
			findings, notes = checkManifests(display, data)
		}
		result.Findings = append(result.Findings, findings...)
		result.Notes = append(result.Notes, notes...)
	}
	for _, target := range paths {
		if target == "-" {
			data, err := io.ReadAll(io.LimitReader(stdin, maxFileBytes+1))
			if err != nil {
				return result, err
			}
			if len(data) > maxFileBytes {
				return result, fmt.Errorf("standard input is larger than %d MB", maxFileBytes>>20)
			}
			check("-", "-", data, "yaml")
			continue
		}
		info, err := os.Stat(target)
		if err != nil {
			return result, err
		}
		if !info.IsDir() {
			data, err := readLimited(target)
			if err != nil {
				return result, err
			}
			check(target, filepath.ToSlash(target), data, map[bool]string{true: "dockerfile", false: "yaml"}[IsDockerfile(target)])
			continue
		}
		err = filepath.WalkDir(target, func(full string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if full != target && (skippedDirs[entry.Name()] || strings.HasPrefix(entry.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() || (!IsDockerfile(full) && !isYAML(full)) {
				return nil
			}
			if len(result.Files) >= maxFiles {
				return fmt.Errorf("more than %d files to check under %s", maxFiles, target)
			}
			data, err := readLimited(full)
			if err != nil {
				result.Notes = append(result.Notes, err.Error())
				return nil
			}
			display := filepath.ToSlash(full)
			if rel, err := filepath.Rel(target, full); err == nil && target != "." {
				display = filepath.ToSlash(filepath.Join(target, rel))
			}
			check(full, display, data, "")
			return nil
		})
		if err != nil {
			return result, err
		}
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return result, nil
}

var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

func readLimited(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d MB and was skipped", name, maxFileBytes>>20)
	}
	return data, nil
}

// dockerignoreNear reports whether a .dockerignore sits next to a
// Dockerfile, where docker build usually finds it.
func dockerignoreNear(dockerfile string) bool {
	if dockerfile == "-" {
		return true
	}
	dir := filepath.Dir(dockerfile)
	for _, name := range []string{".dockerignore", filepath.Base(dockerfile) + ".dockerignore"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func finding(id, file string, line int, title, detail string) Finding {
	rule := ruleByID(id)
	if len(rule.STIG) > 0 {
		detail += " " + STIGNote(rule.STIG)
	}
	return Finding{Rule: id, Severity: rule.Severity, Title: title, Detail: detail, File: file, Line: line, STIG: rule.STIG}
}

// STIGNote names the DISA Kubernetes STIG rules a finding fails, for its detail.
func STIGNote(ids []string) string {
	return "DISA Kubernetes STIG: " + strings.Join(ids, ", ") + "."
}
