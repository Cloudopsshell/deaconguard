package checks

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Paths is the attack path check: it looks for the ways an account on the
// machine could become root (sudo rules, groups, files root runs that
// others can change, setuid programs and capabilities, root's PATH), and
// for secrets other accounts can read. It only reads: the files it lists,
// their permissions, and the SSH keys accounts trust, as fingerprints. The
// contents of a secret never leave the machine; only its path does.
const Paths = "paths"

const pathsTimeout = 3 * time.Minute

// The rules of the attack path check. DG-AP-020, an SSH key trusted on
// many machines, is the server's: only it sees every machine.
const (
	RuleSudoAll        = "DG-AP-001"
	RuleSudoShell      = "DG-AP-002"
	RuleRootGroup      = "DG-AP-003"
	RuleSocket         = "DG-AP-004"
	RuleWritableByRoot = "DG-AP-005"
	RuleRootPath       = "DG-AP-006"
	RuleSetuidShell    = "DG-AP-007"
	RuleCapability     = "DG-AP-008"
	RulePrivateKey     = "DG-AP-010"
	RuleCredentials    = "DG-AP-011"
	RuleEnvFile        = "DG-AP-012"
	RuleSharedKey      = "DG-AP-020"
)

// maxPathFiles bounds how many files each part of the check lists, so a
// machine with thousands of home directories or units stays quick.
const maxPathFiles = 500

// The fixed system directories searched for setuid programs and
// capabilities; FS-11 in the hardening audit covers setuid programs
// anywhere else.
const systemBinaries = "/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin"

var pathFacts = []fact{
	{"groups", "getent group docker lxd disk"},
	{"sockets", "for f in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock /run/containerd/containerd.sock; do [ -e \"$f\" ] && stat -Lc '%a %u %g %U %G %n' \"$f\"; done"},
	{"setuid", "find -H " + systemBinaries + " -maxdepth 1 -type f -perm -4000 2>/dev/null | head -n 500"},
	{"capabilities", "if command -v getcap >/dev/null; then getcap -r " + systemBinaries + " 2>/dev/null | head -n 500; else echo " + noGetcap + "; fi"},
	{"environment", "grep -sE '^[[:space:]]*PATH=' /etc/environment"},
	{"units", "systemctl show -p Id -p User -p ExecStart -p FragmentPath $(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}' | head -n 300) 2>/dev/null"},
	// Secrets: in each login account's home, a few levels deep, and in the
	// usual places for web sites and applications. Only names and
	// permissions are read.
	{"secrets", `{ awk -F: '($3==0||$3>=1000)&&$6!="/"{print $6}' /etc/passwd | sort -u | head -n 500 | while IFS= read -r h; do [ -d "$h" ] && find "$h" -maxdepth 3 -type f \( -path '*/.ssh/*' -o -path '*/.aws/credentials' -o -path '*/.config/gcloud/*.json' -o -path '*/.config/gcloud/credentials.db' -o -path '*/.azure/*.json' -o -path '*/.kube/config' -o -path '*/.docker/config.json' -o -name .netrc -o -name .git-credentials -o -name .pgpass -o -name .my.cnf -o -name '.env' -o -name '.env.*' \) -exec stat -c '%a %u %g %U %G %n' {} + 2>/dev/null; done; ` +
		`find /var/www /srv /opt -maxdepth 4 -type f \( -name '.env' -o -name '.env.*' -o -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' -o -name '*.key' -o -name '*-key.pem' -o -name '*_key.pem' \) -exec stat -c '%a %u %g %U %G %n' {} + 2>/dev/null; ` +
		`find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -exec stat -c '%a %u %g %U %G %n' {} + 2>/dev/null; } | head -n 2000`},
}

// Root reads sudoers, root's crontabs and the SSH keys every account
// trusts, which the server compares between machines.
var pathRootFacts = []fact{
	{"sudoers", `grep -HsvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/*`},
	{"cron", `grep -HsvE '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/root /var/spool/cron/root | head -n 500; ` +
		`for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do for f in "$d"/*; do [ -f "$f" ] && echo "$f:@script $f"; done; done`},
	{SectionKeys, changeRootFacts[1].command},
}

// statScript reads the permissions of each path on its input, one a line.
// Paths come from the machine's own files, so they are passed as data,
// never put into the command.
const statScript = `while IFS= read -r f; do stat -Lc '%a %u %g %U %G %n' -- "$f" 2>/dev/null; done`

const noGetcap = "@@no-getcap@@"

// Programs that open a shell or write any file when run as root, from
// sudo or with the setuid bit: whoever may run them is root.
var shellEscapes = map[string]bool{}

func init() {
	for _, name := range strings.Fields(`awk gawk mawk nawk bash sh dash zsh ksh csh tcsh fish ash busybox env find vi vim view rvim nvim nano pico ed emacs less more man
		python python2 python3 perl ruby irb php node lua tclsh expect gdb strace ltrace git tar zip rsync scp ssh ftp socat nmap docker podman
		apt apt-get dpkg yum dnf rpm pip pip3 npm make cp mv tee dd chmod chown install sed xargs time timeout nice ionice taskset script
		screen tmux watch flock unshare nsenter chroot openssl wget curl su sudo`) {
		shellEscapes[name] = true
	}
}

// Programs that are setuid by design; the setuid rule doesn't report them.
var setuidByDesign = map[string]bool{"su": true, "sudo": true}

// Capabilities that give root: changing user, reading or writing any file,
// loading kernel modules, tracing root's processes.
var rootCapabilities = []string{"cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_chown", "cap_fowner"}

// rootGroups are groups whose members can become root: docker and lxd run
// containers that mount the machine's disk, and disk reads and writes the
// disk itself.
var rootGroups = map[string]string{
	"docker": "starts a container that mounts the machine's disk, as root",
	"lxd":    "starts a container that mounts the machine's disk, as root",
	"disk":   "reads and writes the raw disk, so any file, including /etc/shadow",
}

// The PATH root uses when nothing sets another.
const defaultRootPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// permissions is one line of statScript's output.
type permissions struct {
	mode       uint64
	uid, gid   string
	user, grp  string
	name       string
	directory  bool
	sticky     bool
	worldWrite bool
	groupWrite bool
	worldRead  bool
	groupRead  bool
}

func parsePermissions(line string) (permissions, bool) {
	fields := strings.SplitN(line, " ", 6)
	if len(fields) < 6 {
		return permissions{}, false
	}
	mode, err := strconv.ParseUint(fields[0], 8, 32)
	if err != nil {
		return permissions{}, false
	}
	return permissions{mode: mode, uid: fields[1], gid: fields[2], user: fields[3], grp: fields[4], name: fields[5],
		sticky: mode&01000 != 0, worldWrite: mode&02 != 0, groupWrite: mode&020 != 0, worldRead: mode&04 != 0, groupRead: mode&040 != 0}, true
}

// changers says who other than root can change a file root runs, or ""
// when nobody can.
func (m permissions) changers() string {
	var who []string
	if m.uid != "0" {
		who = append(who, "its owner "+m.user)
	}
	if m.groupWrite && m.gid != "0" {
		who = append(who, "group "+m.grp)
	}
	if m.worldWrite {
		who = []string{"every account"}
	}
	return strings.Join(who, " and ")
}

// readers says who other than its owner can read a secret, or "" for
// nobody. A group named after its owner is the owner's own.
func (m permissions) readers() string {
	switch {
	case m.worldRead:
		return "every account"
	case m.groupRead && m.gid != "0" && m.grp != m.user:
		return "group " + m.grp
	}
	return ""
}

// rootRun is a file root runs, and why.
type rootRun struct {
	file, via string
}

// lowerPriority makes the check's shell, and every command it starts, the
// machine's lowest CPU priority, so it never competes with real work.
const lowerPriority = "renice -n 19 -p $$ >/dev/null 2>&1; "

func runPaths(executor *Executor) Result {
	output, _, err := executor.Run(lowerPriority+script(pathFacts), 4<<20, pathsTimeout)
	if err != nil && len(output) == 0 {
		return failed(fmt.Errorf("read the machine: %w", err))
	}
	facts := sections(output)
	root := false
	if rootOutput, _, privileged, err := executor.RunPrivileged(lowerPriority+script(pathRootFacts), 4<<20, pathsTimeout); privileged && (err == nil || len(rootOutput) > 0) {
		root = true
		for name, body := range sections(rootOutput) {
			facts[name] = body
		}
	}
	analysis := analysePaths(facts, root)
	if files := analysis.toStat(); len(files) > 0 {
		input := []byte(strings.Join(files, "\n") + "\n")
		statOutput, _, _, _ := executor.RunPrivilegedInput(lowerPriority+statScript, input, 1<<20, pathsTimeout)
		analysis.modes = map[string]permissions{}
		for _, line := range lines(statOutput) {
			if mode, ok := parsePermissions(line); ok {
				analysis.modes[mode.name] = mode
			}
		}
	}
	return analysis.result()
}

// pathAnalysis is what the check read, before and after the permissions
// of the files root runs.
type pathAnalysis struct {
	facts     map[string]string
	root      bool
	findings  []Finding
	notes     []string
	runs      []rootRun
	pathDirs  []string
	modes     map[string]permissions
	keys      []SnapshotItem
	counted   map[string]int
	truncated bool
}

// analysePaths reads everything but the permissions of the files root
// runs, which toStat lists for a second read.
func analysePaths(facts map[string]string, root bool) *pathAnalysis {
	a := &pathAnalysis{facts: facts, root: root, counted: map[string]int{}}
	if root {
		a.sudoers()
		a.cron()
	}
	a.groups()
	a.sockets()
	a.units()
	a.setuid()
	a.capabilities()
	a.secrets()
	a.rootPath()
	if root {
		if snapshot := ReadSnapshot(map[string]string{SectionKeys: facts[SectionKeys]}, true); snapshot != nil {
			a.keys = snapshot.Sections[SectionKeys]
		}
	}
	return a
}

func (a *pathAnalysis) add(finding Finding) {
	a.findings = append(a.findings, finding)
}

// sudoAlias matches alias definitions, which the check doesn't expand.
var sudoAlias = regexp.MustCompile(`^(User|Runas|Host|Cmnd)_Alias\b`)

// sudoTag matches a tag before commands, such as "NOPASSWD:".
var sudoTag = regexp.MustCompile(`^(NO)?(PASSWD|EXEC|SETENV|LOG_INPUT|LOG_OUTPUT|MAIL|FOLLOW|INTERCEPT):`)

// sudoers reports rules that give root without a password, or through a
// command that opens a shell.
func (a *pathAnalysis) sudoers() {
	aliases := false
	for _, line := range lines([]byte(a.facts["sudoers"])) {
		file, rule, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		rule = strings.TrimSpace(rule)
		if strings.HasPrefix(rule, "Defaults") {
			if _, value, ok := strings.Cut(rule, "secure_path"); ok {
				value = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "=")), `"`)
				a.pathDirs = append(a.pathDirs, strings.Split(value, ":")...)
			}
			continue
		}
		if sudoAlias.MatchString(rule) {
			aliases = true
			continue
		}
		if strings.HasPrefix(rule, "@include") || strings.HasPrefix(rule, "#include") {
			continue
		}
		who, rest, found := strings.Cut(rule, " ")
		_, commands, hasEquals := strings.Cut(rest, "=")
		if !found || !hasEquals || who == "root" {
			continue
		}
		commands = strings.TrimSpace(commands)
		// "(ALL:ALL)" or "(root)" runs as root; "(postgres)" doesn't.
		if strings.HasPrefix(commands, "(") {
			runas, after, closed := strings.Cut(commands[1:], ")")
			if !closed {
				continue
			}
			users, _, _ := strings.Cut(runas, ":")
			users = strings.TrimSpace(users)
			if users != "" && !strings.Contains(users, "ALL") && !strings.Contains(users, "root") {
				continue
			}
			commands = strings.TrimSpace(after)
		}
		account := who
		if strings.HasPrefix(who, "%") {
			account = "group " + strings.TrimPrefix(who, "%")
		}
		noPassword := false
		for _, command := range strings.Split(commands, ",") {
			command = strings.TrimSpace(command)
			for {
				tag := sudoTag.FindString(command)
				if tag == "" {
					break
				}
				switch tag {
				case "NOPASSWD:":
					noPassword = true
				case "PASSWD:":
					noPassword = false
				}
				command = strings.TrimSpace(command[len(tag):])
			}
			fields := strings.Fields(command)
			if len(fields) == 0 {
				continue
			}
			evidence := file + ": " + truncate(rule, 200)
			program := path.Base(fields[0])
			switch {
			case fields[0] == "ALL":
				if noPassword {
					a.add(Finding{Rule: RuleSudoAll, Severity: "MEDIUM", Title: "Root without a password for " + account,
						Detail: "A sudo rule gives " + account + " root without asking for a password, so any program running as " + account + ", or anyone who gets into it, is root at once. " +
							"Ask for the password: remove NOPASSWD from the rule with visudo, or limit it to the commands needed.",
						Evidence: evidence, Path: []string{account, "sudo, no password", "root"}})
				}
			case shellEscapes[program] || isInterpreter(program):
				severity := "HIGH"
				how := "without a password"
				if !noPassword {
					severity = "MEDIUM"
					how = "with " + account + "'s password"
				}
				a.add(Finding{Rule: RuleSudoShell, Severity: severity, Title: fmt.Sprintf("sudo %s gives %s a root shell", program, account),
					Detail: fmt.Sprintf("A sudo rule lets %s run %s as root %s. %s can open a shell or write any file, so the rule gives full root, not just that command. "+
						"Remove it with visudo, or replace it with a script that does only what is needed and that only root can change.", account, program, how, program),
					Evidence: evidence, Path: []string{account, "sudo " + program, "root"}})
			case strings.HasPrefix(fields[0], "/"):
				a.runs = append(a.runs, rootRun{file: fields[0], via: "sudo rule for " + account})
			}
		}
	}
	if aliases {
		a.notes = append(a.notes, "Some sudoers rules use aliases (Cmnd_Alias, User_Alias), which this check doesn't expand; review those rules by hand.")
	}
}

// cron lists the programs root runs on a schedule.
func (a *pathAnalysis) cron() {
	for _, line := range lines([]byte(a.facts["cron"])) {
		file, entry, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if script, ok := strings.CutPrefix(entry, "@script "); ok {
			a.runs = append(a.runs, rootRun{file: script, via: "cron, from " + path.Dir(script)})
			continue
		}
		fields := strings.Fields(entry)
		if len(fields) == 0 || envLinePattern.MatchString(fields[0]) {
			continue
		}
		// "@daily cmd", or five time fields then the command; the system
		// crontabs put the user before the command.
		skip := 5
		if strings.HasPrefix(fields[0], "@") {
			skip = 1
		}
		system := file == "/etc/crontab" || strings.HasPrefix(file, "/etc/cron.d/")
		if system {
			if len(fields) <= skip || fields[skip] != "root" {
				continue
			}
			skip++
		}
		if len(fields) <= skip {
			continue
		}
		for _, program := range commandFiles(fields[skip:]) {
			a.runs = append(a.runs, rootRun{file: program, via: "root's cron job in " + file})
		}
	}
}

// commandFiles picks the files a command line runs, such as the program
// and the script it is given: its first few absolute paths.
func commandFiles(fields []string) []string {
	var files []string
	for _, field := range fields {
		field = strings.TrimRight(field, ";&|")
		if strings.HasPrefix(field, "/") && len(field) > 1 {
			files = append(files, field)
			if len(files) == 3 {
				break
			}
		}
	}
	return files
}

// isInterpreter matches versioned interpreters such as python3.11.
func isInterpreter(program string) bool {
	for _, name := range []string{"python", "perl", "ruby", "php", "nodejs", "node", "lua"} {
		if strings.HasPrefix(program, name) {
			rest := strings.TrimPrefix(program, name)
			if rest == "" || strings.Trim(rest, "0123456789.") == "" {
				return true
			}
		}
	}
	return false
}

// groups reports the members of groups that give root.
func (a *pathAnalysis) groups() {
	for _, line := range lines([]byte(a.facts["groups"])) {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[3] == "" {
			continue
		}
		why, known := rootGroups[fields[0]]
		if !known {
			continue
		}
		for _, member := range strings.Split(fields[3], ",") {
			if member = strings.TrimSpace(member); member == "" || member == "root" {
				continue
			}
			a.add(Finding{Rule: RuleRootGroup, Severity: "HIGH", Title: fmt.Sprintf("%s is in the %s group, which is root", member, fields[0]),
				Detail: fmt.Sprintf("Members of %s are root in all but name: %s %s. Keep only the accounts that must be root in it (gpasswd -d %s %s), "+
					"and treat them as administrators.", fields[0], member, why, member, fields[0]),
				Evidence: line, Path: []string{member, fields[0] + " group", "root"}})
		}
	}
}

// sockets reports container runtime sockets other accounts can write:
// whoever writes to one starts a root container.
func (a *pathAnalysis) sockets() {
	for _, line := range lines([]byte(a.facts["sockets"])) {
		mode, ok := parsePermissions(line)
		if !ok {
			continue
		}
		who := ""
		switch {
		case mode.worldWrite:
			who = "every account"
		case mode.groupWrite && mode.gid != "0" && rootGroups[mode.grp] == "":
			who = "group " + mode.grp
		}
		if who == "" {
			continue
		}
		severity := "HIGH"
		if mode.worldWrite {
			severity = "CRITICAL"
		}
		a.add(Finding{Rule: RuleSocket, Severity: severity, Title: fmt.Sprintf("%s can use %s, which is root", capitalize(who), mode.name),
			Detail: fmt.Sprintf("%s can write to the container runtime's socket, so it can start a container that mounts the machine's disk as root. "+
				"Only root and the runtime's own group should: chmod 660 %s, and restart the runtime if it recreates the socket.", capitalize(who), mode.name),
			Evidence: line, Path: []string{who, mode.name, "root"}})
	}
}

// units lists the programs and unit files of services running as root.
func (a *pathAnalysis) units() {
	var id, user, fragment string
	var programs []string
	flush := func() {
		if id != "" {
			if fragment != "" {
				a.runs = append(a.runs, rootRun{file: fragment, via: "the unit file of " + id})
			}
			if user == "" || user == "root" || user == "0" {
				for _, program := range programs {
					a.runs = append(a.runs, rootRun{file: program, via: "service " + id + ", as root"})
				}
			}
		}
		id, user, fragment, programs = "", "", "", nil
	}
	for _, line := range strings.Split(a.facts["units"], "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			if strings.TrimSpace(line) == "" {
				flush()
			}
			continue
		}
		switch key {
		case "Id":
			if id != "" {
				flush()
			}
			id = value
		case "User":
			user = value
		case "FragmentPath":
			if strings.HasPrefix(value, "/etc/") {
				fragment = value
			}
		case "ExecStart":
			// "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; … }"
			if _, rest, ok := strings.Cut(value, "path="); ok {
				program, _, _ := strings.Cut(rest, " ")
				if strings.HasPrefix(program, "/") {
					programs = append(programs, program)
				}
			}
		}
	}
	flush()
}

// setuid reports setuid-root programs in system directories that open a
// shell.
func (a *pathAnalysis) setuid() {
	// /bin is often a link to /usr/bin, so a program can be listed twice.
	seen := map[string]bool{}
	for _, file := range lines([]byte(a.facts["setuid"])) {
		program := path.Base(file)
		if seen[program] || setuidByDesign[program] || !(shellEscapes[program] || isInterpreter(program)) {
			continue
		}
		seen[program] = true
		a.add(Finding{Rule: RuleSetuidShell, Severity: "HIGH", Title: fmt.Sprintf("%s is setuid root and opens a shell", file),
			Detail: fmt.Sprintf("%s runs as root for whoever starts it, and can open a shell or write any file, so every account on the machine can become root. "+
				"Remove the setuid bit (chmod u-s %s) unless you know why it is there; if you don't, the machine may have been tampered with.", program, file),
			Evidence: file, Path: []string{"every account", "setuid " + program, "root"}})
	}
}

// capabilities reports programs whose file capabilities give root.
func (a *pathAnalysis) capabilities() {
	body := a.facts["capabilities"]
	if strings.Contains(body, noGetcap) {
		a.notes = append(a.notes, "getcap isn't installed (libcap2-bin or libcap), so file capabilities weren't read.")
		return
	}
	for _, line := range lines([]byte(body)) {
		// "/usr/bin/python3.11 cap_setuid=ep" or "/usr/bin/ping = cap_net_raw+ep"
		file, caps, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		var risky []string
		for _, capability := range rootCapabilities {
			if strings.Contains(caps, capability) {
				risky = append(risky, capability)
			}
		}
		if len(risky) == 0 {
			continue
		}
		program := path.Base(file)
		severity := "MEDIUM"
		if shellEscapes[program] || isInterpreter(program) {
			severity = "HIGH"
		}
		a.add(Finding{Rule: RuleCapability, Severity: severity, Title: fmt.Sprintf("%s has %s", file, strings.Join(risky, ", ")),
			Detail: fmt.Sprintf("Every account that can run %s gets %s, which is enough to become root (by changing user, or reading or writing any file). "+
				"Remove it (setcap -r %s) unless the program needs it and can't be misused.", program, strings.Join(risky, ", "), file),
			Evidence: line, Path: []string{"every account", program + " with " + risky[0], "root"}})
	}
}

// Secret files and what they open.
var secretKinds = []struct {
	match func(name string) bool
	rule  string
	what  string
}{
	{func(name string) bool { return strings.Contains(name, "/.ssh/") && privateKeyName(path.Base(name)) }, RulePrivateKey, "a private SSH key"},
	{func(name string) bool { return strings.HasPrefix(name, "/etc/ssh/ssh_host_") }, RulePrivateKey, "the machine's private SSH host key"},
	{func(name string) bool { return privateKeyName(path.Base(name)) }, RulePrivateKey, "a private key"},
	{func(name string) bool { return strings.HasSuffix(name, "/.aws/credentials") }, RuleCredentials, "AWS credentials"},
	{func(name string) bool { return strings.Contains(name, "/.config/gcloud/") }, RuleCredentials, "Google Cloud credentials"},
	{func(name string) bool { return strings.Contains(name, "/.azure/") }, RuleCredentials, "Azure credentials"},
	{func(name string) bool { return strings.HasSuffix(name, "/.kube/config") }, RuleCredentials, "a Kubernetes login"},
	{func(name string) bool { return strings.HasSuffix(name, "/.docker/config.json") }, RuleCredentials, "registry logins"},
	{func(name string) bool {
		return strings.HasSuffix(name, "/.netrc") || strings.HasSuffix(name, "/.git-credentials")
	}, RuleCredentials, "saved passwords"},
	{func(name string) bool {
		return strings.HasSuffix(name, "/.pgpass") || strings.HasSuffix(name, "/.my.cnf")
	}, RuleCredentials, "database passwords"},
	{func(name string) bool { return envFile(path.Base(name)) }, RuleEnvFile, "application settings, which usually hold passwords and API keys"},
}

// privateKeyName matches private key file names: id_rsa but not id_rsa.pub.
func privateKeyName(name string) bool {
	if strings.HasSuffix(name, ".pub") {
		return false
	}
	return strings.HasPrefix(name, "id_") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, "-key.pem") || strings.HasSuffix(name, "_key.pem") ||
		strings.HasSuffix(name, "_key")
}

func envFile(name string) bool {
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return false
	}
	for _, example := range []string{"example", "sample", "template", "dist", "defaults"} {
		if strings.HasSuffix(name, "."+example) {
			return false
		}
	}
	return true
}

// secrets reports secret files that accounts other than their owner can
// read. The file's contents are never read.
func (a *pathAnalysis) secrets() {
	seen := map[string]bool{}
	for _, line := range lines([]byte(a.facts["secrets"])) {
		mode, ok := parsePermissions(line)
		if !ok || seen[mode.name] {
			continue
		}
		seen[mode.name] = true
		readers := mode.readers()
		if readers == "" {
			continue
		}
		for _, kind := range secretKinds {
			if !kind.match(mode.name) {
				continue
			}
			severity := "HIGH"
			if kind.rule == RuleEnvFile && !mode.worldRead {
				severity = "MEDIUM"
			}
			a.counted[kind.rule]++
			if a.counted[kind.rule] > maxPathFiles/10 {
				a.truncated = true
				break
			}
			owner := mode.user
			a.add(Finding{Rule: kind.rule, Severity: severity, Title: fmt.Sprintf("%s can read %s, %s", capitalize(readers), mode.name, kind.what),
				Detail: fmt.Sprintf("%s holds %s and belongs to %s, but %s can read it, so a break-in into any of those accounts leads to whatever it opens. "+
					"Only its owner should read it: chmod 600 %s. If others may have read it, replace the secret.", mode.name, kind.what, owner, readers, mode.name),
				Evidence: fmt.Sprintf("%s %s:%s %s", strconv.FormatUint(mode.mode, 8), mode.user, mode.grp, mode.name),
				Path:     []string{readers, "reads " + mode.name, secretTarget(kind.rule, owner)}})
			break
		}
	}
}

func secretTarget(rule, owner string) string {
	switch rule {
	case RulePrivateKey:
		return "logs in where " + owner + "'s key is trusted"
	case RuleCredentials:
		return owner + "'s accounts"
	}
	return "the application's passwords and keys"
}

// rootPath lists the directories of root's PATH, from sudo's secure_path,
// /etc/environment and the default.
func (a *pathAnalysis) rootPath() {
	for _, line := range lines([]byte(a.facts["environment"])) {
		_, value, _ := strings.Cut(line, "=")
		a.pathDirs = append(a.pathDirs, strings.Split(strings.Trim(strings.TrimSpace(value), `"'`), ":")...)
	}
	a.pathDirs = append(a.pathDirs, strings.Split(defaultRootPath, ":")...)
	seen := map[string]bool{}
	var dirs []string
	for _, dir := range a.pathDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" || !strings.HasPrefix(dir, "/") || seen[dir] {
			continue
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	a.pathDirs = dirs
}

// toStat lists the files root runs, their directories, and root's PATH,
// for their permissions.
func (a *pathAnalysis) toStat() []string {
	seen := map[string]bool{}
	var files []string
	add := func(file string) {
		if !seen[file] && len(files) < maxPathFiles*2 && !strings.ContainsAny(file, "\n\r") {
			seen[file] = true
			files = append(files, file)
		}
	}
	for _, run := range a.runs {
		add(run.file)
		for dir := path.Dir(run.file); dir != "/" && dir != "."; dir = path.Dir(dir) {
			add(dir)
		}
	}
	for _, dir := range a.pathDirs {
		add(dir)
	}
	return files
}

// writable reports the files root runs and the directories of root's PATH
// that others can change, once the permissions are read.
func (a *pathAnalysis) writable() {
	if a.modes == nil {
		return
	}
	reported := map[string]bool{}
	for _, run := range a.runs {
		target, how := run.file, ""
		mode, ok := a.modes[run.file]
		if ok {
			how = mode.changers()
		}
		// A directory others can write lets them replace the file, unless
		// the sticky bit keeps them to their own files.
		if how == "" {
			for dir := path.Dir(run.file); dir != "/" && dir != "."; dir = path.Dir(dir) {
				if dirMode, ok := a.modes[dir]; ok && !dirMode.sticky {
					if who := dirMode.changers(); who != "" {
						target, how = dir, who
						break
					}
				}
			}
		}
		if how == "" || reported[target+" "+run.via] {
			continue
		}
		reported[target+" "+run.via] = true
		severity := "HIGH"
		if strings.Contains(how, "every account") {
			severity = "CRITICAL"
		}
		subject := "it"
		if target != run.file {
			subject = "its directory " + target
		}
		a.add(Finding{Rule: RuleWritableByRoot, Severity: severity, Title: fmt.Sprintf("%s can change %s, which root runs", capitalize(how), run.file),
			Detail: fmt.Sprintf("Root runs %s (%s), and %s can change %s, so they can make root run anything. Make it and its directories owned by root "+
				"and writable only by root: chown root:root and chmod go-w.", run.file, run.via, how, subject),
			Evidence: permissionEvidence(a.modes[target]), Path: []string{how, "changes " + target, run.via, "root"}})
	}
	for _, dir := range a.pathDirs {
		mode, ok := a.modes[dir]
		if !ok {
			continue
		}
		how := mode.changers()
		if how == "" {
			continue
		}
		severity := "HIGH"
		if mode.worldWrite {
			severity = "CRITICAL"
		}
		a.add(Finding{Rule: RuleRootPath, Severity: severity, Title: fmt.Sprintf("%s can write to %s, in root's PATH", capitalize(how), dir),
			Detail: fmt.Sprintf("%s is in the PATH root uses, and %s can put programs in it. A program there named like a common command (ls, systemctl) runs as root "+
				"the next time root types it. Make it owned by root and writable only by root: chown root:root %s; chmod 755 %s.", dir, how, dir, dir),
			Evidence: permissionEvidence(mode), Path: []string{how, "a program in " + dir, "root runs it"}})
	}
}

func permissionEvidence(mode permissions) string {
	if mode.name == "" {
		return ""
	}
	return fmt.Sprintf("%s %s:%s %s", strconv.FormatUint(mode.mode, 8), mode.user, mode.grp, mode.name)
}

func capitalize(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// result is the check's result, once the permissions are read.
func (a *pathAnalysis) result() Result {
	a.writable()
	sort.SliceStable(a.findings, func(i, j int) bool {
		return severityRank(a.findings[i].Severity) < severityRank(a.findings[j].Severity)
	})
	result := Result{Status: StatusCompleted, Privileged: a.root, Findings: a.findings, Notes: a.notes, Keys: a.keys}
	if result.Findings == nil {
		result.Findings = []Finding{}
	}
	if result.Notes == nil {
		result.Notes = []string{}
	}
	if len(result.Findings) > maxFindings {
		result.note("Only the first %d of the %d findings are listed.", maxFindings, len(result.Findings))
		result.Findings = result.Findings[:maxFindings]
	}
	if a.truncated {
		result.note("Only the first %d readable secrets of each kind are listed.", maxPathFiles/10)
	}
	paths := 0
	for _, finding := range result.Findings {
		if finding.Rule != RuleEnvFile && finding.Rule != RuleCredentials && finding.Rule != RulePrivateKey {
			paths++
		}
	}
	result.Summary = fmt.Sprintf("%s to root, %s readable by others", plural(paths, "way", "ways"), plural(len(result.Findings)-paths, "secret", "secrets"))
	if !a.root {
		result.Status = StatusPartial
		result.note("Without sudo, sudoers rules, root's cron jobs and the SSH keys accounts trust were not read, and secrets in other accounts' homes may be missed.")
	}
	return result
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}
