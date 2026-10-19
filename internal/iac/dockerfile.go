package iac

import (
	"fmt"
	"regexp"
	"strings"
)

const dockerSource = "Docker build best practices"

var dockerfileRules = []Rule{
	{ID: "DG-DF-001", Severity: "HIGH", Title: "The image runs as root", Source: dockerSource},
	{ID: "DG-DF-002", Severity: "MEDIUM", Title: "The base image isn't pinned to a version", Source: dockerSource},
	{ID: "DG-DF-003", Severity: "HIGH", Title: "A secret is set in the image", Source: dockerSource},
	{ID: "DG-DF-004", Severity: "MEDIUM", Title: "A script is downloaded and run without being checked", Source: dockerSource},
	{ID: "DG-DF-005", Severity: "MEDIUM", Title: "ADD downloads a file from a URL", Source: dockerSource},
	{ID: "DG-DF-006", Severity: "LOW", Title: "ADD copies local files; COPY is clearer", Source: dockerSource},
	{ID: "DG-DF-007", Severity: "MEDIUM", Title: "The image uses sudo", Source: dockerSource},
	{ID: "DG-DF-008", Severity: "MEDIUM", Title: "The image exposes SSH", Source: dockerSource},
	{ID: "DG-DF-009", Severity: "MEDIUM", Title: "Files are made writable by everyone", Source: dockerSource},
	{ID: "DG-DF-010", Severity: "LOW", Title: "No .dockerignore: the build context may include secrets", Source: dockerSource},
	{ID: "DG-DF-011", Severity: "LOW", Title: "No HEALTHCHECK", Source: dockerSource},
}

// instruction is one Dockerfile instruction, continuation lines joined.
type instruction struct {
	command, arguments string
	line               int
}

func parseDockerfile(text string) []instruction {
	var result []instruction
	var current strings.Builder
	start := 0
	escape := `\`
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for index, raw := range lines {
		line := strings.TrimSpace(raw)
		if current.Len() == 0 {
			if line == "" || strings.HasPrefix(line, "#") {
				if strings.HasPrefix(strings.ToLower(line), "# escape=`") {
					escape = "`"
				}
				continue
			}
			start = index + 1
		} else if strings.HasPrefix(line, "#") {
			continue // comments inside a continued instruction
		}
		if strings.HasSuffix(line, escape) {
			current.WriteString(strings.TrimSuffix(line, escape) + " ")
			continue
		}
		current.WriteString(line)
		command, arguments, _ := strings.Cut(strings.TrimSpace(current.String()), " ")
		result = append(result, instruction{command: strings.ToUpper(command), arguments: strings.TrimSpace(arguments), line: start})
		current.Reset()
	}
	if current.Len() > 0 {
		command, arguments, _ := strings.Cut(strings.TrimSpace(current.String()), " ")
		result = append(result, instruction{command: strings.ToUpper(command), arguments: strings.TrimSpace(arguments), line: start})
	}
	return result
}

// notSecret are variable names that hold where a secret is, not the secret.
var notSecret = regexp.MustCompile(`(?i)_(FILE|PATH|DIR|NAME|URL|ENDPOINT|ID|REF|KEYRING|LENGTH|TTL|EXPIRY)$`)

// looksSecret reports whether a variable name and value set a secret: a
// secret-like name with a value that isn't a path or a reference.
func looksSecret(name, value string) bool {
	value = strings.Trim(value, `"'`)
	return secretName.MatchString(name) && !notSecret.MatchString(name) && value != "" &&
		!strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "$")
}

var (
	secretName  = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credentials?)`)
	pipeToShell = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
	worldWrite  = regexp.MustCompile(`\bchmod\s+(-R\s+)?(0?777|a\+w|o\+w|\+w)\b`)
	sudoWord    = regexp.MustCompile(`(^|[\s;&|(])sudo\s`)
	urlPattern  = regexp.MustCompile(`(?i)^(https?|ftp)://`)
)

// ignoreComment accepts findings in a Dockerfile: "# deaconguard:ignore
// DG-DF-011 DG-DF-002" anywhere in it.
var ignoreComment = regexp.MustCompile(`(?im)^\s*#\s*deaconguard:ignore\s+(.+)$`)

// checkDockerfile checks one Dockerfile, leaving out the rules its ignore
// comments name.
func checkDockerfile(file, text string, hasDockerignore bool) []Finding {
	ignored := map[string]bool{}
	for _, match := range ignoreComment.FindAllStringSubmatch(text, -1) {
		for _, id := range strings.FieldsFunc(match[1], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			ignored[strings.ToUpper(id)] = true
		}
	}
	var kept []Finding
	for _, f := range dockerfileFindings(file, text, hasDockerignore) {
		if !ignored[f.Rule] {
			kept = append(kept, f)
		}
	}
	return kept
}

// dockerfileFindings checks one Dockerfile. Only the last stage becomes the
// image, so the user and health check are checked there.
func dockerfileFindings(file, text string, hasDockerignore bool) []Finding {
	instructions := parseDockerfile(text)
	var findings []Finding
	stages := map[string]bool{}
	lastFrom, lastUser, lastUserLine, healthcheck, copiesContext := 0, "", 0, false, false
	for _, in := range instructions {
		switch in.command {
		case "FROM":
			lastFrom, lastUser, lastUserLine, healthcheck = in.line, "", 0, false
			fields := strings.Fields(in.arguments)
			image := ""
			for _, field := range fields {
				if !strings.HasPrefix(field, "--") {
					image = field
					break
				}
			}
			lower := strings.ToLower(image)
			earlierStage := stages[lower]
			// A stage's name counts from the FROM that names it on.
			for index, field := range fields {
				if strings.EqualFold(field, "AS") && index+1 < len(fields) {
					stages[strings.ToLower(fields[index+1])] = true
				}
			}
			if image == "" || lower == "scratch" || earlierStage || strings.Contains(image, "$") {
				break
			}
			if strings.Contains(image, "@") {
				break // pinned by digest
			}
			last := image[strings.LastIndex(image, "/")+1:]
			if !strings.Contains(last, ":") || strings.HasSuffix(image, ":latest") {
				findings = append(findings, finding("DG-DF-002", file, in.line,
					fmt.Sprintf("FROM %s: the base image isn't pinned to a version", image),
					"Name a version tag, such as debian:12, or better a digest (image@sha256:…), so every build starts from the same base and its vulnerabilities are known."))
			}
		case "USER":
			lastUser, lastUserLine = strings.TrimSpace(in.arguments), in.line
		case "HEALTHCHECK":
			healthcheck = !strings.EqualFold(strings.TrimSpace(in.arguments), "NONE")
		case "ENV", "ARG":
			for _, name := range assignedNames(in.arguments, in.command == "ARG") {
				if looksSecret(name.key, name.value) {
					findings = append(findings, finding("DG-DF-003", file, in.line,
						fmt.Sprintf("%s %s: a secret is set in the image", in.command, name.key),
						"Anyone who can pull the image can read ENV and ARG values in its history. Pass secrets at build time with RUN --mount=type=secret, and at run time from the orchestrator's secrets."))
				}
			}
		case "RUN":
			if pipeToShell.MatchString(in.arguments) {
				findings = append(findings, finding("DG-DF-004", file, in.line, "RUN downloads a script and runs it without checking it",
					"Download the file, check it against a published SHA-256 checksum or signature, then run it; or install from the distribution's signed packages."))
			}
			if sudoWord.MatchString(in.arguments) {
				findings = append(findings, finding("DG-DF-007", file, in.line, "RUN uses sudo",
					"Build steps already run as root until a USER instruction: drop sudo, and don't install it in the image, where it lets a compromised process become root."))
			}
			if worldWrite.MatchString(in.arguments) {
				findings = append(findings, finding("DG-DF-009", file, in.line, "RUN makes files writable by everyone",
					"Give the application's user ownership instead (chown, or COPY --chown), with modes such as 755 for folders and 644 for files."))
			}
		case "ADD":
			sources := strings.Fields(in.arguments)
			var plain []string
			for _, source := range sources {
				if !strings.HasPrefix(source, "--") {
					plain = append(plain, source)
				}
			}
			if len(plain) >= 2 {
				remote, archive := false, false
				for _, source := range plain[:len(plain)-1] {
					remote = remote || urlPattern.MatchString(source) || strings.HasPrefix(source, "git@")
					lower := strings.ToLower(source)
					archive = archive || strings.HasSuffix(lower, ".tar") || strings.Contains(lower, ".tar.") || strings.HasSuffix(lower, ".tgz")
				}
				switch {
				case remote && !strings.Contains(in.arguments, "--checksum="):
					findings = append(findings, finding("DG-DF-005", file, in.line, "ADD downloads a file from a URL without a checksum",
						"Add --checksum=sha256:… to ADD, or download with curl and check the file's checksum, so a changed or tampered download fails the build."))
				case !remote && !archive:
					findings = append(findings, finding("DG-DF-006", file, in.line, "ADD copies local files",
						"Use COPY for local files: ADD also unpacks archives and downloads URLs, which is easy to trigger by accident."))
				}
			}
		case "EXPOSE":
			for _, port := range strings.Fields(in.arguments) {
				if strings.TrimSuffix(port, "/tcp") == "22" {
					findings = append(findings, finding("DG-DF-008", file, in.line, "EXPOSE 22: the image exposes SSH",
						"Containers don't need an SSH server: use docker exec or kubectl exec to get a shell, and leave sshd out of the image."))
				}
			}
		case "COPY":
			fields := strings.Fields(in.arguments)
			for _, field := range fields {
				if field == "." || field == "./" {
					copiesContext = true
				}
			}
		}
	}
	if lastFrom == 0 {
		return findings // not a Dockerfile after all
	}
	switch {
	case lastUser == "":
		findings = append(findings, finding("DG-DF-001", file, lastFrom, "The image runs as root: its last stage has no USER",
			"Add a USER instruction with an unprivileged user, such as USER 10001, after installing packages, so a compromised process isn't root in the container."))
	case isRoot(lastUser):
		findings = append(findings, finding("DG-DF-001", file, lastUserLine, fmt.Sprintf("USER %s: the image runs as root", lastUser),
			"End the last stage with a USER instruction for an unprivileged user, such as USER 10001."))
	}
	if !healthcheck {
		findings = append(findings, finding("DG-DF-011", file, lastFrom, "The image has no HEALTHCHECK",
			"Add a HEALTHCHECK so Docker can tell a running but broken container; on Kubernetes, liveness and readiness probes do this instead."))
	}
	if copiesContext && !hasDockerignore {
		findings = append(findings, finding("DG-DF-010", file, lastFrom, "COPY . without a .dockerignore",
			"Add a .dockerignore next to the Dockerfile that leaves out .git, .env, keys and build output, so they aren't copied into the image."))
	}
	return findings
}

func isRoot(user string) bool {
	name, _, _ := strings.Cut(user, ":")
	return name == "root" || name == "0"
}

type assignment struct {
	key, value string
}

// assignedNames reads ENV and ARG: "KEY=value KEY2=value2", the old
// "KEY value", or, for ARG, "KEY" without a default.
func assignedNames(arguments string, isArg bool) []assignment {
	fields := strings.Fields(arguments)
	if len(fields) == 0 {
		return nil
	}
	if !strings.Contains(fields[0], "=") {
		if isArg || len(fields) < 2 {
			return []assignment{{key: fields[0]}}
		}
		return []assignment{{key: fields[0], value: strings.Join(fields[1:], " ")}}
	}
	var result []assignment
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if found && key != "" {
			result = append(result, assignment{key: key, value: value})
		}
	}
	return result
}
