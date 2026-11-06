//go:build linux

package live

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// procMachine answers the rules' questions from /proc, which in Kubernetes
// is the node's (the node agent shares its process namespace), and from
// the machine's /etc/passwd.
type procMachine struct {
	hostRoot string
	mu       sync.Mutex
	users    map[uint32]string
	readAt   time.Time
}

func newProcMachine(hostRoot string) *procMachine {
	return &procMachine{hostRoot: hostRoot}
}

func proc(pid uint32, name string) string {
	return "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/" + name
}

func (m *procMachine) Executable(pid uint32) string {
	target, _ := os.Readlink(proc(pid, "exe"))
	return target
}

func (m *procMachine) HasTerminal(pid uint32) bool {
	fields := procStat(int(pid))
	// After the name: state, ppid, pgrp, session, tty_nr.
	if len(fields) < 5 {
		return false
	}
	tty, err := strconv.Atoi(fields[4])
	return err == nil && tty != 0
}

func (m *procMachine) Ancestors(pid uint32) []string {
	var names []string
	current := int(pid)
	for range 6 {
		fields := procStat(current)
		if len(fields) < 2 {
			break
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent <= 1 {
			break
		}
		comm, err := os.ReadFile("/proc/" + strconv.Itoa(parent) + "/comm")
		if err != nil {
			break
		}
		names = append(names, strings.TrimSpace(string(comm)))
		current = parent
	}
	return names
}

func (m *procMachine) WorkingDirectory(pid uint32) string {
	directory, _ := os.Readlink(proc(pid, "cwd"))
	return directory
}

func (m *procMachine) Parent(pid uint32) uint32 {
	fields := procStat(int(pid))
	if len(fields) < 2 {
		return 0
	}
	parent, _ := strconv.ParseUint(fields[1], 10, 32)
	return uint32(parent)
}

// socketInode is the inode of the socket open as the process's file
// descriptor fd, or "".
func socketInode(pid uint32, fd int) string {
	target, err := os.Readlink(proc(pid, "fd/"+strconv.Itoa(fd)))
	if err != nil {
		return ""
	}
	inode, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return ""
	}
	return strings.TrimSuffix(inode, "]")
}

// NetworkStdio reads the process's standard input and output, and when
// both are sockets, finds them among the TCP connections of the process's
// network namespace. Most processes' input isn't a socket, so the common
// case is one readlink.
func (m *procMachine) NetworkStdio(pid uint32) string {
	input := socketInode(pid, 0)
	if input == "" {
		return ""
	}
	output := socketInode(pid, 1)
	if output == "" {
		return ""
	}
	peers := map[string]string{}
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		file, err := os.Open(proc(pid, table))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || (fields[9] != input && fields[9] != output) {
				continue
			}
			peers[fields[9]] = tcpAddress(fields[2])
		}
		file.Close()
	}
	if peers[input] == "" || peers[output] == "" {
		return ""
	}
	return peers[input]
}

// tcpAddress reads an address as /proc/net/tcp writes it: the address in
// hex, as the kernel holds it in 32-bit words, a colon, and the port.
func tcpAddress(text string) string {
	hexAddress, hexPort, ok := strings.Cut(text, ":")
	raw, err := hex.DecodeString(hexAddress)
	if !ok || err != nil || (len(raw) != 4 && len(raw) != 16) {
		return ""
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return ""
	}
	// Each 32-bit word is written in the machine's byte order: little
	// endian on the machines the agent supports.
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	address, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(address.Unmap(), uint16(port)).String()
}

// User names uid from the machine's /etc/passwd, read again every five
// minutes, so new accounts are named.
func (m *procMachine) User(uid uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.users == nil || time.Since(m.readAt) > 5*time.Minute {
		m.users = map[uint32]string{}
		m.readAt = time.Now()
		root := m.hostRoot
		if root == "" {
			root = "/"
		}
		if file, err := os.Open(filepath.Join(root, "etc/passwd")); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), ":")
				if len(fields) < 3 {
					continue
				}
				if id, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
					m.users[uint32(id)] = fields[0]
				}
			}
			file.Close()
		}
	}
	if name, ok := m.users[uid]; ok {
		return name
	}
	return "uid " + strconv.FormatUint(uint64(uid), 10)
}

// selfUsage is the agent's own CPU time and memory, from /proc/self.
func selfUsage() (cpu time.Duration, memoryBytes uint64) {
	if fields := procStat(os.Getpid()); len(fields) > 12 {
		// utime and stime, in clock ticks of 1/100 s.
		user, _ := strconv.ParseUint(fields[11], 10, 64)
		system, _ := strconv.ParseUint(fields[12], 10, 64)
		cpu = time.Duration(user+system) * 10 * time.Millisecond
	}
	if raw, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if value, ok := strings.CutPrefix(line, "VmRSS:"); ok {
				kilobytes, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(value), " kB"), 10, 64)
				memoryBytes = kilobytes * 1024
			}
		}
	}
	return cpu, memoryBytes
}

func (m *procMachine) EffectiveUID(pid uint32) (uint32, bool) {
	raw, err := os.ReadFile(proc(pid, "status"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if value, ok := strings.CutPrefix(line, "Uid:"); ok {
			// Real, effective, saved and filesystem IDs, as seen from the
			// agent's user namespace: the machine's.
			fields := strings.Fields(value)
			if len(fields) < 2 {
				return 0, false
			}
			effective, err := strconv.ParseUint(fields[1], 10, 32)
			return uint32(effective), err == nil
		}
	}
	return 0, false
}

func (m *procMachine) Privileged(pid uint32) bool {
	executable := proc(pid, "exe")
	program, err := os.Readlink(executable)
	if err != nil || !systemProgram(program) {
		return false
	}
	// /proc/PID/exe opens the process's own program, whichever mount
	// namespace it is in.
	info, err := os.Stat(executable)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	if info.Mode()&os.ModeSetuid != 0 {
		return true
	}
	size, err := unix.Getxattr(executable, "security.capability", nil)
	return err == nil && size > 0
}

// HostPID finds the process caller knows as nsPID. In the agent's own
// process namespace that is nsPID itself; in a container's, the process
// in the same namespace whose innermost ID is nsPID.
func (m *procMachine) HostPID(caller, nsPID uint32) uint32 {
	namespace, err := os.Readlink(proc(caller, "ns/pid"))
	if err != nil {
		return 0
	}
	if own, err := os.Readlink("/proc/self/ns/pid"); err == nil && own == namespace {
		return nsPID
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	want := strconv.FormatUint(uint64(nsPID), 10)
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		if other, err := os.Readlink(proc(uint32(pid), "ns/pid")); err != nil || other != namespace {
			continue
		}
		raw, err := os.ReadFile(proc(uint32(pid), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if value, ok := strings.CutPrefix(line, "NSpid:"); ok {
				fields := strings.Fields(value)
				if len(fields) > 0 && fields[len(fields)-1] == want {
					return uint32(pid)
				}
				break
			}
		}
	}
	return 0
}

func (m *procMachine) Name(pid uint32) string {
	comm, err := os.ReadFile(proc(pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}

func (m *procMachine) FilePath(pid uint32, fd int) string {
	target, _ := os.Readlink(proc(pid, "fd/"+strconv.Itoa(fd)))
	return target
}

func (m *procMachine) Cmdline(pid uint32) []string {
	raw, err := os.ReadFile(proc(pid, "cmdline"))
	if err != nil {
		return nil
	}
	return strings.FieldsFunc(string(raw), func(r rune) bool { return r == 0 })
}
