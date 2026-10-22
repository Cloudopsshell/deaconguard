//go:build linux

package containers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"deaconguard/internal/gobinary"
)

// ErrSymlink means a path inside a container went through a symbolic link,
// which is never followed: a container could otherwise point one at a file
// on the host, and the agent, which runs as root, would read it.
var ErrSymlink = errors.New("goes through a symbolic link, which isn't followed")

// root is a container's root directory, opened once.
type root struct {
	fd  int
	dev uint64
}

// openRoot opens a container's root, such as /proc/1234/root. That magic
// link is the one link followed: it is the kernel's way to a process's root.
func openRoot(path string) (*root, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &root{fd: fd, dev: uint64(stat.Dev)}, nil
}

func (r *root) close() { unix.Close(r.fd) }

// Device identifies the container root's file system.
func (r *root) Device() uint64 { return r.dev }

// openDir opens a directory inside the root, one component at a time,
// refusing symbolic links and "..".
func (r *root) openDir(path string, flags int) (int, error) {
	fd, err := unix.Dup(r.fd)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			unix.Close(fd)
			return -1, fmt.Errorf("%s: \"..\" isn't allowed", path)
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, fmt.Errorf("%s %w", path, ErrSymlink)
		}
		if err != nil {
			return -1, err
		}
		fd = next
	}
	if flags == unix.O_PATH {
		return fd, nil
	}
	// Reopen the directory itself for reading its entries.
	readable, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	return readable, err
}

// readFile reads at most limit bytes of a regular file inside the root,
// without following any symbolic link on the way. It reports whether the
// file was longer than limit.
func (r *root) ReadFile(path string, limit int64) ([]byte, bool, error) {
	cut := strings.LastIndex(path, "/")
	dir, name := path[:cut+1], path[cut+1:]
	if name == "" || name == "." || name == ".." {
		return nil, false, fmt.Errorf("%s: not a file", path)
	}
	dirfd, err := r.openDir(dir, unix.O_PATH)
	if err != nil {
		return nil, false, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, false, fmt.Errorf("%s %w", path, ErrSymlink)
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// ReadDir lists a directory inside the root without following links.
// Symbolic links are listed as neither directories nor regular files.
func (r *root) ReadDir(path string) ([]Entry, error) {
	fd, err := r.openDir(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(names))
	for _, name := range names {
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		mode := stat.Mode & unix.S_IFMT
		entries = append(entries, Entry{Name: name, IsDir: mode == unix.S_IFDIR, IsReg: mode == unix.S_IFREG, Size: stat.Size, Dev: uint64(stat.Dev),
			Exec: mode == unix.S_IFREG && stat.Mode&0o111 != 0})
	}
	return entries, nil
}

// ReadGoBinary reads a Go program's build information inside the root,
// without following any symbolic link, streaming through the file.
func (r *root) ReadGoBinary(path string) ([]byte, error) {
	cut := strings.LastIndex(path, "/")
	dir, name := path[:cut+1], path[cut+1:]
	if name == "" || name == "." || name == ".." {
		return nil, fmt.Errorf("%s: not a file", path)
	}
	dirfd, err := r.openDir(dir, unix.O_PATH)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	start := make([]byte, 4)
	if _, err := io.ReadFull(file, start); err != nil || !gobinary.Executable(start) {
		return nil, gobinary.ErrNotGo
	}
	info, err := gobinary.Read(io.MultiReader(bytes.NewReader(start), file), gobinary.MaxProgramBytes)
	if err != nil {
		return nil, err
	}
	return info.Record(), nil
}
