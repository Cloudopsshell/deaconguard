// Package live is DeaconGuard's live detection: watchers in the Linux
// kernel report programs that start and writes to sensitive files as they
// happen, and the agent's rules turn the suspicious ones into alerts.
//
// The watchers (bpf/watch.c) and their loader (kernel_linux.go) are
// DeaconGuard's own; nothing else is involved between the agent and the
// kernel. This file holds the rules, which run anywhere, so they can be
// tested without a kernel.
package live

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// The rules' IDs.
const (
	RuleTempProgram  = "DG-RT-001"
	RuleServiceShell = "DG-RT-002"
	RuleMiner        = "DG-RT-003"
	RuleDownloadRun  = "DG-RT-004"
	RuleAccounts     = "DG-RT-010"
	RuleSudoers      = "DG-RT-011"
	RuleSSHLogins    = "DG-RT-012"
	RulePersistence  = "DG-RT-013"
)

// Alert is what a rule found, as the agent sends it to the server.
type Alert struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	PID      uint32 `json:"pid"`
	User     string `json:"user"`
	// Program is the program that started, or that wrote the file.
	Program string `json:"program"`
	// Parent is the program that started it.
	Parent string `json:"parent,omitempty"`
	// Command is the program's command line, with secrets masked.
	Command string `json:"command,omitempty"`
	// Path is the file written.
	Path string `json:"path,omitempty"`
	// Test marks the alert "Send a test alert" asked for.
	Test bool `json:"test,omitempty"`
	// Repeats counts the same alerts left out since this one was last sent.
	Repeats int `json:"repeats,omitempty"`
}

// Machine answers what the rules need to know beyond the event, from /proc
// and /etc/passwd. Each call is made only for events a rule already
// suspects, so the common case reads nothing.
type Machine interface {
	// Executable is where /proc/PID/exe points, or "".
	Executable(pid uint32) string
	// HasTerminal reports whether the process has a controlling terminal,
	// as a person typing a command does.
	HasTerminal(pid uint32) bool
	// Ancestors are the names of the process's parent, grandparent and so
	// on, nearest first, at most a few.
	Ancestors(pid uint32) []string
	// WorkingDirectory is the process's current directory, or "".
	WorkingDirectory(pid uint32) string
	// User is the account name for uid.
	User(uid uint32) string
}

// testProgramName starts the name of the program "Send a test alert" runs
// from a temporary folder. The agent starts it itself, so it's a test, not
// an attack.
const testProgramName = "deaconguard-test-"

// agentName is the agent's process name, which programs it starts carry
// until they replace it: at most 15 characters, as the kernel keeps it.
var agentName = func() string {
	name := "deaconguard"
	if executable, err := os.Executable(); err == nil {
		name = filepath.Base(executable)
	}
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}()

// Watched paths, for the kernel's filter: writes elsewhere never reach the
// agent. HomeSSH is matched as /home/NAME/.ssh/.
var watchedPrefixes = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
	"/etc/sudoers",
	"/etc/ssh/sshd_config", "/root/.ssh/",
	"/etc/cron", "/var/spool/cron/",
	"/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/",
	"/etc/ld.so.preload", "/etc/rc.local",
}

const homeSSHPrefix, homeSSHAfter = "/home/", ".ssh/"

// watchedNames are the file names watched when a program writes them by a
// relative path, from inside their folder.
var watchedNames = []string{
	"passwd", "shadow", "group", "gshadow", "sudoers", "sshd_config",
	"authorized_keys", "authorized_keys2", "crontab", "ld.so.preload", "rc.local",
}

var temporaryFolders = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

// shells start a command line.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true, "mksh": true, "csh": true, "tcsh": true, "fish": true}

// services are long-running servers that have no reason to start a shell:
// one that does is running a command an attacker gave it. Process names
// are at most 15 characters.
var services = []string{
	"nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm", "php-cgi",
	"mysqld", "mariadbd", "redis-server", "mongod", "memcached", "uwsgi",
}

// minerNames are crypto miners' usual program names.
var minerNames = regexp.MustCompile(`(?i)^(xmrig|xmr-stak|minerd|cpuminer|ethminer|nbminer|lolminer|t-rex|teamredminer|cgminer|bfgminer|srbminer|kdevtmpfsi|kinsing|nanominer|phoenixminer|gminer)`)

// miningPool matches a mining pool address in a command line.
var miningPool = regexp.MustCompile(`(?i)\bstratum\+(tcp|ssl|tls)://`)

// downloadToShell matches a command line that downloads a script and pipes
// it straight into a shell.
var downloadToShell = regexp.MustCompile(`\b(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+\s+)?(/\S*/)?(ba|da|z|k)?sh\b`)

// packageTools change system files as part of installing or updating
// software; what they write isn't reported.
var packageTools = map[string]bool{
	"dpkg": true, "apt": true, "apt-get": true, "aptitude": true, "unattended-upgr": true, "packagekitd": true,
	"dnf": true, "yum": true, "rpm": true, "microdnf": true, "dnf-automatic": true, "zypper": true, "apk": true,
	"pacman": true, "snapd": true, "systemd-sysuser": true, "systemd-tmpfile": true,
}

// adminTools are what people use to change accounts, sudo rules, SSH keys
// and scheduled jobs. A change made with one is reported, but as medium:
// it's most likely someone on your team.
var adminTools = map[string]bool{
	"useradd": true, "usermod": true, "userdel": true, "adduser": true, "deluser": true,
	"groupadd": true, "groupmod": true, "groupdel": true, "addgroup": true, "delgroup": true,
	"passwd": true, "chpasswd": true, "chage": true, "chsh": true, "chfn": true, "gpasswd": true, "newusers": true,
	"vipw": true, "vigr": true, "visudo": true, "crontab": true, "systemctl": true, "systemd": true,
	"ssh-copy-id": true, "cloud-init": true,
}

// Evaluate applies the rules to one event.
func Evaluate(event Event, machine Machine) []Alert {
	switch event.Kind {
	case KindExec:
		return evaluateExec(event, machine)
	case KindWrite:
		if alert, ok := evaluateWrite(event, machine); ok {
			return []Alert{alert}
		}
	}
	return nil
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func isService(name string) bool {
	for _, service := range services {
		if strings.HasPrefix(name, service) {
			return true
		}
	}
	return false
}

func evaluateExec(event Event, machine Machine) []Alert {
	program := path.Base(event.Path)
	base := Alert{PID: event.PID, User: machine.User(event.UID), Program: event.Path, Parent: event.Parent, Command: maskSecrets(event.Args)}
	var alerts []Alert
	add := func(rule, severity, title, detail string) {
		alert := base
		alert.Rule, alert.Severity, alert.Title, alert.Detail = rule, severity, title, detail
		alerts = append(alerts, alert)
	}

	// The agent's own test program, from the machine's temporary folder
	// (under /host for the node agent in Kubernetes).
	if strings.Contains(event.Path, "/tmp/"+testProgramName) && event.Parent == agentName {
		alert := base
		alert.Rule, alert.Severity, alert.Test = RuleTempProgram, "LOW", true
		alert.Title = "Test alert: live detection works end to end"
		alert.Detail = "Started by the agent for \"Send a test alert\": the kernel saw the program start, the agent's rule matched, and the server received the alert."
		return []Alert{alert}
	}
	temporary := hasPrefix(event.Path, temporaryFolders)
	// go test and go run build programs in /tmp/go-build… and run them
	// from there: expected on build machines when the go tool starts them.
	if temporary && event.Parent == "go" && strings.HasPrefix(event.Path, "/tmp/go-build") {
		temporary = false
	}
	from := path.Dir(event.Path)
	// A program run from memory, with memfd_create and fexecve, starts as
	// /dev/fd/N; where its executable points tells.
	if !temporary && (strings.HasPrefix(event.Path, "/dev/fd/") || strings.HasPrefix(event.Path, "/proc/")) {
		if executable := machine.Executable(event.PID); strings.HasPrefix(executable, "/memfd:") || strings.HasSuffix(executable, " (deleted)") {
			temporary = true
			from = "memory"
			base.Program = executable
		}
	}
	if temporary {
		where := "from " + from
		if from == "memory" {
			where = "from memory, without a file"
		}
		add(RuleTempProgram, "HIGH", fmt.Sprintf("A program started %s", where),
			fmt.Sprintf("%s started %s. Programs rarely run from temporary folders or memory; attackers put their tools there because anyone can write to them. "+
				"Find out what it is and what started it (%s); if nobody on your team ran it, treat the machine as compromised.", event.Path, where, orUnknown(event.Parent)))
	}

	if shells[program] && isService(event.Parent) {
		add(RuleServiceShell, "CRITICAL", fmt.Sprintf("A shell started under %s", event.Parent),
			fmt.Sprintf("%s, a server that has no reason to run commands, started %s. This is how a web shell, an injected command or an exploited service shows: "+
				"look at the command, at the service's recent requests or queries, and isolate the machine if you can't explain it.", event.Parent, program))
	}

	// A shell that starts a miner is reported when the miner starts.
	if minerNames.MatchString(program) || minerNames.MatchString(event.Comm) || (!shells[program] && miningPool.MatchString(event.Args)) {
		add(RuleMiner, "CRITICAL", fmt.Sprintf("A crypto miner started: %s", program),
			"A program with a crypto miner's name, or one given a mining pool's address, started. Miners are what most break-ins on servers install. "+
				"Stop it, find how it got there (cron, systemd, a container) and remove that too.")
	}

	if shells[program] && downloadToShell.MatchString(event.Args) && !machine.HasTerminal(event.PID) {
		add(RuleDownloadRun, "HIGH", "A downloaded script was piped into a shell",
			"A shell ran a command that downloads a script and runs it at once, with no person at a terminal: from a scheduled job, a service or a script. "+
				"Attackers use it to fetch their next stage. Check where it downloads from and what started it.")
	}
	return alerts
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

// sensitive says which rule a written path falls under. Only the files
// themselves count, not the lock files, temporary copies and backups tools
// write next to them: tools write a copy and rename it onto the file, and
// that rename is reported.
func sensitive(file string) (rule, severity, what string, ok bool) {
	name := path.Base(file)
	folder := path.Dir(file)
	switch {
	case file == "/etc/passwd" || file == "/etc/shadow" || file == "/etc/group" || file == "/etc/gshadow":
		return RuleAccounts, "HIGH", "the accounts and passwords", true
	// sudo reads every file in sudoers.d but those with a dot in their name
	// or ending in ~.
	case file == "/etc/sudoers" || folder == "/etc/sudoers.d" && !strings.Contains(name, ".") && !strings.HasSuffix(name, "~"):
		return RuleSudoers, "HIGH", "who may use sudo", true
	case file == "/etc/ssh/sshd_config" || folder == "/etc/ssh/sshd_config.d" && strings.HasSuffix(name, ".conf"):
		return RuleSSHLogins, "HIGH", "how the SSH server lets people log in", true
	case strings.HasSuffix(folder, "/.ssh") && (name == "authorized_keys" || name == "authorized_keys2"):
		return RuleSSHLogins, "HIGH", "the SSH keys that may log in as this account", true
	case file == "/etc/ld.so.preload":
		return RulePersistence, "CRITICAL", "a library loaded into every program, a rootkit's favourite place", true
	case temporaryName(name):
		return "", "", "", false
	case file == "/etc/crontab" || folder == "/etc/cron.d" || hasPrefix(folder, []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}) ||
		strings.HasPrefix(file, "/var/spool/cron/") && !strings.HasPrefix(name, "tmp."):
		return RulePersistence, "HIGH", "the scheduled jobs", true
	case hasPrefix(file, []string{"/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/"}) && systemdUnit(name):
		return RulePersistence, "HIGH", "the services started at boot", true
	case file == "/etc/rc.local":
		return RulePersistence, "HIGH", "the commands run at boot", true
	}
	return "", "", "", false
}

// temporaryName matches editors' and tools' working copies.
func temporaryName(name string) bool {
	for _, suffix := range []string{"~", ".swp", ".swx", ".tmp", ".lock", ".bak", ".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".rpmnew", ".rpmsave"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return strings.HasPrefix(name, ".#")
}

// systemdUnit matches the files systemd reads in a unit folder: units, and
// drop-in settings.
func systemdUnit(name string) bool {
	for _, suffix := range []string{".service", ".timer", ".socket", ".path", ".mount", ".automount", ".target", ".conf"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// usualPlace is where each watched name lives, for a relative write whose
// folder couldn't be read.
var usualPlace = map[string]string{
	"passwd": "/etc/passwd", "shadow": "/etc/shadow", "group": "/etc/group", "gshadow": "/etc/gshadow",
	"sudoers": "/etc/sudoers", "sshd_config": "/etc/ssh/sshd_config", "authorized_keys": "/root/.ssh/authorized_keys",
	"authorized_keys2": "/root/.ssh/authorized_keys2", "crontab": "/etc/crontab", "ld.so.preload": "/etc/ld.so.preload", "rc.local": "/etc/rc.local",
}

// howWritten says what a program did to a file: the watchers see the
// attempt, before the kernel checks it, so a write that then fails, such as
// one refused for lack of rights, is reported too.
var howWritten = map[int]string{HowOpen: "opened for writing", HowRename: "replaced", HowLink: "linked"}

func evaluateWrite(event Event, machine Machine) (Alert, bool) {
	file := event.Path
	unknownFolder := false
	if !strings.HasPrefix(file, "/") {
		if directory := machine.WorkingDirectory(event.PID); directory != "" {
			file = path.Join(directory, file)
		} else if usual, known := usualPlace[path.Base(file)]; known {
			// The program exited before its folder could be read: judge the
			// file by its name, where such a file usually lives.
			file, unknownFolder = usual, true
		}
	}
	rule, severity, what, ok := sensitive(file)
	if !ok {
		return Alert{}, false
	}
	if packageTools[event.Comm] || event.Comm == agentName {
		return Alert{}, false
	}
	tool := ""
	if adminTools[event.Comm] {
		tool = event.Comm
	}
	for _, ancestor := range machine.Ancestors(event.PID) {
		if packageTools[ancestor] || ancestor == agentName {
			return Alert{}, false
		}
		if tool == "" && adminTools[ancestor] && ancestor != "systemd" {
			tool = ancestor
		}
	}
	shown := file
	if unknownFolder {
		shown = fmt.Sprintf("%s (a file named %s; the program exited before its folder could be read)", file, path.Base(event.Path))
	}
	verb := howWritten[event.How]
	if verb == "" {
		verb = howWritten[HowOpen]
	}
	alert := Alert{Rule: rule, Severity: severity, PID: event.PID, User: machine.User(event.UID), Program: event.Comm, Path: file,
		Title:  fmt.Sprintf("%s %s by %s", file, verb, event.Comm),
		Detail: fmt.Sprintf("%s %s %s, which controls %s, and it wasn't the package manager. ", event.Comm, verb, shown, what)}
	if tool != "" && severity != "CRITICAL" {
		alert.Severity = "MEDIUM"
		alert.Detail += fmt.Sprintf("It was made with %s, so most likely by someone on your team; check that it was meant.", tool)
	} else {
		alert.Detail += "If nobody on your team made this change, look at what changed and how the program got there: attackers change these files to keep their access."
	}
	return alert, true
}

// secretArgument matches passwords and tokens in a command line, and
// urlPassword the password in a URL such as https://user:pass@host; they
// are masked before an alert leaves the machine.
var (
	secretArgument = regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|token|secret|api[_-]?key|auth)[^=:\s]*[=:]\s*|Bearer\s+|(?:\s-u\s*|--user[=\s])[^:\s'"]+:|\s-p)[^\s'"&@]+`)
	urlPassword    = regexp.MustCompile(`(://[^:/\s@]+:)[^@\s/]+@`)
)

func maskSecrets(command string) string {
	masked := urlPassword.ReplaceAllString(command, "${1}***@")
	masked = secretArgument.ReplaceAllStringFunc(masked, func(match string) string {
		return secretArgument.FindStringSubmatch(match)[1] + "***"
	})
	if len(masked) > 512 {
		masked = masked[:512]
	}
	return masked
}
