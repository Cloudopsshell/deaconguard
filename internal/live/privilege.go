package live

// The rules for privilege changes, kernel modules and one process taking
// control of another. Like the others, they run anywhere and are tested
// without a kernel; Machine answers what the event doesn't say.

import (
	"fmt"
	"path"
	"strings"
)

const (
	RulePrivilege   = "DG-RT-030"
	RuleModule      = "DG-RT-031"
	RuleTrace       = "DG-RT-032"
	RuleMemoryWrite = "DG-RT-033"
)

// errExists is the error a module load returns when the module is already
// loaded: nothing changed.
const errExists = 17

// unchanged is the user ID that leaves an ID as it was.
const unchanged = 0xffffffff

// systemFolders are where the system's own programs are installed.
var systemFolders = []string{
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/",
	"/lib/", "/lib64/", "/snap/",
}

// systemProgram reports whether a program's path is one of the system's
// own folders, and the file is still there.
func systemProgram(program string) bool {
	return hasPrefix(program, systemFolders) && !strings.HasSuffix(program, " (deleted)")
}

// fromTemporary reports whether a program runs from a temporary folder or
// from memory.
func fromTemporary(program string) bool {
	return hasPrefix(program, temporaryFolders) || strings.HasPrefix(program, "/memfd:") || strings.HasSuffix(program, " (deleted)")
}

// setuidNames are the system's usual setuid programs, by process name: a
// process that ended before its program could be checked is judged by its
// name instead.
var setuidNames = map[string]bool{
	"sudo": true, "sudo-rs": true, "su": true, "pkexec": true, "doas": true, "newgrp": true, "sg": true,
	"passwd": true, "chsh": true, "chfn": true, "gpasswd": true, "chage": true, "expiry": true,
	"mount": true, "umount": true, "fusermount": true, "fusermount3": true, "ping": true,
	"unix_chkpwd": true, "polkit-agent-he": true, "dbus-daemon-lau": true, "Xorg.wrap": true,
	"snap-confine": true, "ksu": true, "ssh-keysign": true, "newuidmap": true, "newgidmap": true,
	"mount.nfs": true, "mount.cifs": true, "ntfs-3g": true, "pppd": true, "at": true, "crontab": true,
	"cockpit-session": true, "userhelper": true,
}

// moduleLoaders are the programs that load kernel modules on an ordinary
// system: kmod's tools, and udev and systemd loading drivers at boot.
var moduleLoaders = map[string]bool{
	"modprobe": true, "insmod": true, "kmod": true, "systemd-udevd": true, "(udev-worker)": true,
	"systemd-modules": true, "nvidia-modprobe": true,
}

// debuggers take control of processes for a living.
var debuggers = map[string]bool{
	"gdb": true, "gdbserver": true, "lldb": true, "lldb-server": true, "strace": true, "ltrace": true,
	"perf": true, "dlv": true, "rr": true, "valgrind": true, "py-spy": true, "rbspy": true, "pystack": true,
	"eu-stack": true, "pstack": true, "gcore": true, "criu": true, "jattach": true, "dotnet-dump": true,
	"dotnet-trace": true, "runsc": true, "runsc-sandbox": true,
}

// credentialHolders are processes that hold passwords, keys or sessions:
// taking control of one is how they are stolen.
var credentialHolders = map[string]bool{
	"sshd": true, "sshd-session": true, "sshd-auth": true, "sudo": true, "su": true, "login": true,
	"passwd": true, "gpg-agent": true, "ssh-agent": true, "keepassxc": true, "gnome-keyring-d": true,
	"polkitd": true, "vault": true,
}

// commandLine is the process's command line, with secrets masked.
func commandLine(machine Machine, pid uint32) string {
	return maskSecrets(strings.Join(machine.Cmdline(pid), " "))
}

func firstAncestor(machine Machine, pid uint32) string {
	if ancestors := machine.Ancestors(pid); len(ancestors) > 0 {
		return ancestors[0]
	}
	return ""
}

// describeIDs says what a privilege change asked for, as the program
// called it.
func describeIDs(event Event) string {
	id := func(value uint32) string {
		if value == unchanged {
			return "-1"
		}
		return fmt.Sprint(value)
	}
	switch event.How {
	case CallSetREUID:
		return fmt.Sprintf("setreuid(%s, %s)", id(event.IDs[0]), id(event.IDs[1]))
	case CallSetRESUID:
		return fmt.Sprintf("setresuid(%s, %s, %s)", id(event.IDs[0]), id(event.IDs[1]), id(event.IDs[2]))
	}
	return fmt.Sprintf("setuid(%s)", id(event.IDs[0]))
}

// evaluatePrivilege looks at a process that isn't root switching to root.
// The system lets only programs owned by root and marked setuid (sudo, su,
// passwd), or given the capability with setcap, do that; anything else
// that manages it has usually exploited a flaw to get there.
func evaluatePrivilege(event Event, machine Machine) []Alert {
	if event.Result != 0 {
		return nil
	}
	// Root inside a user namespace, as rootless containers and sandboxes
	// use, or only the saved ID set to root, isn't root on the machine.
	if effective, known := machine.EffectiveUID(event.PID); known && effective != 0 {
		return nil
	}
	program := machine.Executable(event.PID)
	ended := program == ""
	if ended {
		program = event.Comm
	}
	suspicious := event.Marked || fromTemporary(program)
	if !suspicious {
		if !ended && machine.Privileged(event.PID) {
			return nil
		}
		if ended && setuidNames[event.Comm] {
			return nil
		}
	}
	user := machine.User(event.UID)
	alert := Alert{Rule: RulePrivilege, Severity: "HIGH", PID: event.PID, User: user, Program: program,
		Parent: firstAncestor(machine, event.PID), Command: commandLine(machine, event.PID),
		Title: fmt.Sprintf("%s became root without sudo or another setuid program", event.Comm)}
	alert.Detail = fmt.Sprintf("%s (%s), running as %s, switched to root with %s. The system lets only its setuid programs, such as sudo and su, "+
		"or programs given the capability with setcap, do that, and this isn't one of them. A process that becomes root any other way has "+
		"usually exploited a flaw in the kernel or in a program. ", event.Comm, program, user, describeIDs(event))
	if ended {
		alert.Detail += "It ended before its program could be checked. "
	}
	if suspicious {
		alert.Severity = "CRITICAL"
		alert.Detail += "It, or a program that started it, ran from a temporary folder or memory, where attackers keep their tools. "
	}
	alert.Detail += "Find out what the program is and what started it; if nobody on your team ran it, treat the machine as compromised."
	return []Alert{alert}
}

// moduleFile reports whether an argument names a kernel module's file.
func moduleFile(argument string) bool {
	for _, suffix := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
		if strings.HasSuffix(argument, suffix) {
			return true
		}
	}
	return false
}

// evaluateModule looks at a kernel module loaded, or a load tried: code
// that runs with the kernel's full power, how rootkits hide.
func evaluateModule(event Event, machine Machine) []Alert {
	if event.Result == -errExists {
		return nil
	}
	file := ""
	if event.How == CallFileModule {
		file = machine.FilePath(event.PID, int(event.Target))
	}
	command := machine.Cmdline(event.PID)
	if file == "" {
		// The program closed the file already, or loaded it from memory
		// (kmod does, for a compressed module): its command line may say.
		for _, argument := range command {
			if moduleFile(argument) {
				file = argument
				if !strings.HasPrefix(file, "/") {
					if directory := machine.WorkingDirectory(event.PID); directory != "" {
						file = path.Join(directory, file)
					}
				}
			}
		}
	}
	program := machine.Executable(event.PID)
	if program == "" {
		program = event.Comm
	}
	standard := moduleLoaders[event.Comm]
	system := strings.Contains(file, "/lib/modules/")
	temporary := event.Marked || fromTemporary(file) || fromTemporary(program)
	severity := ""
	switch {
	case temporary:
		severity = "CRITICAL"
	case standard && (file == "" || system):
		// modprobe and udev loading the system's own drivers.
		return nil
	case !standard && system:
		severity = "MEDIUM"
	default:
		severity = "HIGH"
	}
	shown := file
	if shown == "" {
		shown = "memory"
	}
	verb, outcome := "loaded", ""
	if event.Result < 0 {
		verb = "tried to load"
		outcome = fmt.Sprintf(" The kernel refused it (%s), but someone tried.", errorName(-event.Result))
	}
	name := strings.TrimSuffix(path.Base(file), path.Ext(path.Base(file)))
	name = strings.TrimSuffix(name, ".ko")
	title := fmt.Sprintf("%s %s a kernel module from %s", event.Comm, verb, shown)
	if file != "" {
		title = fmt.Sprintf("%s %s the kernel module %s from %s", event.Comm, verb, name, path.Dir(file))
	}
	detail := fmt.Sprintf("%s (%s) %s a kernel module from %s.%s A module runs with the kernel's full power and can hide files, processes and connections from "+
		"every tool on the machine, which is how rootkits work. ", event.Comm, program, verb, shown, outcome)
	switch {
	case temporary:
		detail += "It came from a temporary folder or memory, or from a program that did, where attackers keep their tools. "
	case !standard:
		detail += "It wasn't loaded by modprobe or udev, which load the system's drivers. "
	default:
		detail += "It isn't one of the system's modules, under /lib/modules. "
	}
	if event.Args != "" {
		detail += fmt.Sprintf("Its parameters: %s. ", maskSecrets(event.Args))
	}
	detail += "If nobody on your team installed it, treat the machine as compromised: a rootkit can't be trusted to show itself, so check the machine from outside."
	return []Alert{{Rule: RuleModule, Severity: severity, PID: event.PID, User: machine.User(event.UID), Program: program,
		Parent: firstAncestor(machine, event.PID), Command: maskSecrets(strings.Join(command, " ")), Path: file, Title: title, Detail: detail}}
}

// evaluateTrace looks at a process taking control of another with
// ptrace, or writing into its memory: how passwords are read out of
// sshd or sudo, and code is injected into a running program.
func evaluateTrace(event Event, machine Machine) []Alert {
	write := event.How == CallVMWrite
	if write && event.Result <= 0 || !write && event.Result != 0 {
		return nil
	}
	target := machine.HostPID(event.PID, event.Target)
	if target == 0 || target == event.PID {
		return nil
	}
	tracer := machine.Executable(event.PID)
	if tracer == "" {
		tracer = event.Comm
	}
	targetName := machine.Name(target)
	targetProgram := machine.Executable(target)
	if targetProgram == "" {
		targetProgram = orUnknown(targetName)
	}
	debugger := debuggers[path.Base(tracer)] || debuggers[event.Comm]
	holder := credentialHolders[targetName]
	temporary := event.Marked || fromTemporary(tracer)
	severity := "HIGH"
	switch {
	case temporary:
		severity = "CRITICAL"
	case holder:
	case debugger && !write && machine.HasTerminal(event.PID):
		// Someone at a terminal debugging a program.
		return nil
	case debugger:
		severity = "MEDIUM"
	}
	user := machine.User(event.UID)
	shownTarget := fmt.Sprintf("%s (process %d)", targetProgram, target)
	alert := Alert{Rule: RuleTrace, Severity: severity, PID: event.PID, User: user, Program: tracer,
		Parent: firstAncestor(machine, event.PID), Command: commandLine(machine, event.PID), Path: shownTarget}
	if write {
		alert.Rule = RuleMemoryWrite
		alert.Title = fmt.Sprintf("%s wrote into the memory of %s", event.Comm, orUnknown(targetName))
		alert.Detail = fmt.Sprintf("%s (%s), running as %s, wrote straight into the memory of %s with process_vm_writev. "+
			"Programs don't change each other's memory; code injected this way runs as the other program, with its rights and its network access, and hides behind its name. ",
			event.Comm, tracer, user, shownTarget)
	} else {
		alert.Title = fmt.Sprintf("%s took control of %s with ptrace", event.Comm, orUnknown(targetName))
		alert.Detail = fmt.Sprintf("%s (%s), running as %s, attached to %s with ptrace, so it can read and change everything the process holds and does. "+
			"Debuggers do this; attackers do it to read passwords and keys out of a running program or to inject code into it. ", event.Comm, tracer, user, shownTarget)
	}
	switch {
	case temporary:
		alert.Detail += "It, or a program that started it, ran from a temporary folder or memory, where attackers keep their tools. "
	case holder:
		alert.Detail += fmt.Sprintf("%s holds passwords, keys or logged-in sessions. ", targetName)
	case debugger:
		alert.Detail += fmt.Sprintf("%s is a debugger, but it ran without a person at a terminal. ", path.Base(tracer))
	}
	alert.Detail += "If nobody on your team was debugging it, stop the program and treat the machine as compromised."
	return []Alert{alert}
}

// errorName says what a module load's error means, for the alert.
func errorName(errno int64) string {
	switch errno {
	case 1:
		return "not permitted"
	case 8:
		return "not a valid module"
	case 13:
		return "permission denied"
	case 22:
		return "invalid module"
	case 61:
		return "no signature, and the kernel requires one"
	case 74, 126, 127, 128, 129:
		return "its signature was rejected"
	}
	return fmt.Sprintf("error %d", errno)
}
