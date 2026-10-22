package containers

// FS is a container's or an image's files, as the readers here need them:
// a running container's through its root (see saferead_linux.go), or an
// image's taken from its layers (internal/images).
type FS interface {
	// ReadFile reads at most limit bytes of a regular file, and reports
	// whether it was longer.
	ReadFile(path string, limit int64) ([]byte, bool, error)
	// ReadDir lists a directory.
	ReadDir(path string) ([]Entry, error)
	// Device identifies the file system; the library walk stays on it.
	Device() uint64
}

// Entry is one directory entry.
type Entry struct {
	Name  string
	IsDir bool
	IsReg bool
	Size  int64
	Dev   uint64
	// Exec: a regular file someone may run, which may be a Go program.
	Exec bool
}

// GoBinaryReader is an FS that can read a compiled Go program's build
// information (a gobinary.Record), without holding the program in memory.
type GoBinaryReader interface {
	ReadGoBinary(path string) ([]byte, error)
}
