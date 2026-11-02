//go:build linux

package live

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
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
