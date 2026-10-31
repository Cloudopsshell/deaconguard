package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Changes is the host change check: it records what an attacker or a
// careless change would add to a machine (ports open to the network,
// accounts, administrators, SSH keys, services, scheduled jobs), and the
// server compares each record with the previous scan's. It is one short
// script that reads a few files and lists; nothing is walked.
const Changes = "changes"

const changesTimeout = 2 * time.Minute

// The snapshot's sections. Those in rootSections need root to be complete;
// without it they are left out, rather than compared half-read.
const (
	SectionListening = "listening"
	SectionUsers     = "users"
	SectionAdmins    = "admins"
	SectionSudoers   = "sudoers"
	SectionKeys      = "keys"
	SectionServices  = "services"
	SectionCron      = "cron"
)

var rootSections = map[string]bool{SectionSudoers: true, SectionKeys: true, SectionCron: true}

var changeFacts = []fact{
	{SectionListening, "if command -v ss >/dev/null; then ss -H -tulnp; elif command -v netstat >/dev/null; then netstat -tulnp; else echo " + noSocketTool + "; fi"},
	{SectionUsers, "cat /etc/passwd"},
	{SectionAdmins, "getent group sudo wheel admin"},
	{SectionServices, "systemctl list-unit-files --state=enabled --no-legend --no-pager --plain --type=service,socket,timer"},
}

// Root reads sudoers, SSH keys as fingerprints (ssh-keygen -l: the key
// itself never leaves the machine) and every crontab.
var changeRootFacts = []fact{
	{SectionSudoers, `grep -HsvE '^[[:space:]]*(#|Defaults|$)' /etc/sudoers /etc/sudoers.d/*`},
	{SectionKeys, `awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1 " " $6}' /etc/passwd | while read -r u h; do ` +
		`for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do [ -f "$f" ] && ssh-keygen -lf "$f" | sed "s|^|$u |"; done; done`},
	{SectionCron, `grep -HsvE '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* | head -n 500; ` +
		`for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do for f in "$d"/*; do [ -f "$f" ] && echo "$f: (script)"; done; done`},
}

// Snapshot is what the change check recorded: per section, its items.
type Snapshot struct {
	Root     bool                      `json:"root"`
	Sections map[string][]SnapshotItem `json:"sections"`
}

// SnapshotItem is one thing on the machine: Key identifies it between
// scans; Text describes it; Exposed marks a port open to the network.
type SnapshotItem struct {
	Key     string `json:"key"`
	Text    string `json:"text"`
	Exposed bool   `json:"exposed,omitempty"`
}

func runChanges(executor *Executor) Result {
	output, _, err := executor.Run(script(changeFacts), 4<<20, changesTimeout)
	if err != nil && len(output) == 0 {
		return failed(fmt.Errorf("read the machine: %w", err))
	}
	facts := sections(output)
	root := false
	if rootOutput, _, privileged, err := executor.RunPrivileged(script(changeRootFacts), 4<<20, changesTimeout); err == nil || len(rootOutput) > 0 {
		root = privileged
		if privileged {
			for name, body := range sections(rootOutput) {
				facts[name] = body
			}
		}
	}
	snapshot := ReadSnapshot(facts, root)
	result := Result{Status: StatusCompleted, Privileged: root, Findings: []Finding{}, Notes: []string{}, Snapshot: snapshot}
	var counts []string
	for _, name := range []string{SectionListening, SectionUsers, SectionAdmins, SectionSudoers, SectionKeys, SectionServices, SectionCron} {
		if items, ok := snapshot.Sections[name]; ok {
			counts = append(counts, fmt.Sprintf("%d %s", len(items), sectionNames[name]))
		}
	}
	result.Summary = "Recorded " + strings.Join(counts, ", ")
	if !root {
		result.Status = StatusPartial
		result.note("Without sudo, sudoers rules, SSH keys and crontabs were not read, so changes to them aren't seen.")
	}
	if _, ok := snapshot.Sections[SectionListening]; !ok {
		result.note("Neither ss nor netstat is installed, so listening ports weren't read.")
	}
	return result
}

var sectionNames = map[string]string{
	SectionListening: "listening ports", SectionUsers: "login accounts", SectionAdmins: "administrators", SectionSudoers: "sudoers rules",
	SectionKeys: "SSH keys", SectionServices: "enabled services", SectionCron: "scheduled jobs",
}

var (
	processPattern = regexp.MustCompile(`users:\(\("([^"]+)"`)
	secretPattern  = regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|token|secret|api[_-]?key|auth)[^=:\s]*[=:]\s*|Bearer\s+|://[^:/\s]+:)[^\s'"&@]+`)
	envLinePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// ReadSnapshot turns the script's sections into a snapshot.
func ReadSnapshot(facts map[string]string, root bool) *Snapshot {
	snapshot := &Snapshot{Root: root, Sections: map[string][]SnapshotItem{}}
	add := func(section string, item SnapshotItem) {
		snapshot.Sections[section] = append(snapshot.Sections[section], item)
	}
	if body, ok := facts[SectionListening]; ok && !strings.Contains(body, noSocketTool) {
		snapshot.Sections[SectionListening] = []SnapshotItem{}
		seen := map[string]bool{}
		for _, line := range lines([]byte(body)) {
			sockets := listening(line)
			if len(sockets) != 1 {
				continue
			}
			socket := sockets[0]
			// Ephemeral UDP ports, such as a DHCP or DNS client's, change
			// with every start.
			if socket.Protocol == "udp" && socket.Port >= 32768 {
				continue
			}
			address := socket.Address
			switch {
			case socket.Exposed:
				address = "*"
			case address == "127.0.0.1" || address == "::1" || strings.HasPrefix(address, "127."):
				address = "localhost"
			}
			key := fmt.Sprintf("%s %s:%d", socket.Protocol, address, socket.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			text := fmt.Sprintf("%s port %d on %s", strings.ToUpper(socket.Protocol), socket.Port, address)
			if address == "*" {
				text = fmt.Sprintf("%s port %d, open to the network", strings.ToUpper(socket.Protocol), socket.Port)
			}
			if match := processPattern.FindStringSubmatch(line); match != nil {
				text += " (" + match[1] + ")"
			} else if fields := strings.Fields(line); len(fields) > 0 && strings.Contains(fields[len(fields)-1], "/") {
				if _, name, found := strings.Cut(fields[len(fields)-1], "/"); found && name != "" {
					text += " (" + name + ")"
				}
			}
			add(SectionListening, SnapshotItem{Key: key, Text: text, Exposed: socket.Exposed})
		}
	}
	if body, ok := facts[SectionUsers]; ok {
		snapshot.Sections[SectionUsers] = []SnapshotItem{}
		for _, line := range lines([]byte(body)) {
			fields := strings.Split(line, ":")
			if len(fields) < 7 || noLogin(fields[6]) {
				continue
			}
			uid, _ := strconv.Atoi(fields[2])
			text := fmt.Sprintf("%s (UID %d, %s)", fields[0], uid, fields[6])
			add(SectionUsers, SnapshotItem{Key: fields[0] + " uid " + fields[2], Text: text})
		}
	}
	if body, ok := facts[SectionAdmins]; ok {
		snapshot.Sections[SectionAdmins] = []SnapshotItem{}
		for _, line := range lines([]byte(body)) {
			fields := strings.Split(line, ":")
			if len(fields) < 4 {
				continue
			}
			for _, member := range strings.Split(fields[3], ",") {
				if member = strings.TrimSpace(member); member != "" {
					add(SectionAdmins, SnapshotItem{Key: member + " in " + fields[0], Text: member + " (group " + fields[0] + ")"})
				}
			}
		}
	}
	if body, ok := facts[SectionServices]; ok {
		snapshot.Sections[SectionServices] = []SnapshotItem{}
		for _, line := range lines([]byte(body)) {
			if fields := strings.Fields(line); len(fields) > 0 && strings.Contains(fields[0], ".") {
				add(SectionServices, SnapshotItem{Key: fields[0], Text: fields[0]})
			}
		}
	}
	if !root {
		return sorted(snapshot)
	}
	if body, ok := facts[SectionSudoers]; ok {
		snapshot.Sections[SectionSudoers] = []SnapshotItem{}
		for _, line := range lines([]byte(body)) {
			file, rule, found := strings.Cut(line, ":")
			if rule = strings.Join(strings.Fields(rule), " "); !found || rule == "" {
				continue
			}
			text := truncate(redact(rule), 200) + " (" + file + ")"
			add(SectionSudoers, SnapshotItem{Key: file + " " + digest(rule), Text: text})
		}
	}
	if body, ok := facts[SectionKeys]; ok {
		snapshot.Sections[SectionKeys] = []SnapshotItem{}
		// "root 256 SHA256:abc… comment (ED25519)"
		for _, line := range lines([]byte(body)) {
			fields := strings.Fields(line)
			if len(fields) < 3 || !strings.HasPrefix(fields[2], "SHA256:") {
				continue
			}
			user, fingerprint := fields[0], fields[2]
			kind, comment := "", ""
			if last := fields[len(fields)-1]; strings.HasPrefix(last, "(") {
				kind = strings.Trim(last, "()")
				comment = strings.Join(fields[3:len(fields)-1], " ")
			}
			text := fmt.Sprintf("%s key for %s, %s", kind, user, fingerprint)
			if comment != "" && comment != "no comment" {
				text += " (" + truncate(comment, 80) + ")"
			}
			add(SectionKeys, SnapshotItem{Key: user + " " + fingerprint, Text: strings.TrimSpace(text)})
		}
	}
	if body, ok := facts[SectionCron]; ok {
		snapshot.Sections[SectionCron] = []SnapshotItem{}
		for _, line := range lines([]byte(body)) {
			file, entry, found := strings.Cut(line, ":")
			if entry = strings.Join(strings.Fields(entry), " "); !found || entry == "" || envLinePattern.MatchString(entry) {
				continue
			}
			add(SectionCron, SnapshotItem{Key: file + " " + digest(entry), Text: file + ": " + truncate(redact(entry), 200)})
		}
	}
	return sorted(snapshot)
}

func noLogin(shell string) bool {
	for _, suffix := range []string{"nologin", "false", "sync", "halt", "shutdown"} {
		if strings.HasSuffix(shell, suffix) {
			return true
		}
	}
	return shell == ""
}

// redact masks what looks like a password or token in a command line, for
// the text shown. The line's key is a hash of it whole, so a changed
// secret is still a change, and the secret never leaves the machine.
func redact(text string) string {
	return secretPattern.ReplaceAllString(text, "${1}***")
}

func sorted(snapshot *Snapshot) *Snapshot {
	for name, items := range snapshot.Sections {
		sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
		snapshot.Sections[name] = items
	}
	return snapshot
}

// digest identifies a line without carrying it.
func digest(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:8])
}
