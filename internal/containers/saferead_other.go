//go:build !linux

package containers

import (
	"errors"
)

// ErrSymlink means a path inside a container went through a symbolic link.
var ErrSymlink = errors.New("goes through a symbolic link, which isn't followed")

var errNotLinux = errors.New("containers can only be read on Linux")

type root struct{ dev uint64 }

func openRoot(string) (*root, error)                         { return nil, errNotLinux }
func (r *root) close()                                       {}
func (r *root) Device() uint64                               { return 0 }
func (r *root) ReadFile(string, int64) ([]byte, bool, error) { return nil, false, errNotLinux }
func (r *root) ReadDir(string) ([]Entry, error)              { return nil, errNotLinux }
func (r *root) ReadGoBinary(string) ([]byte, error)          { return nil, errNotLinux }
