package memlimit

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, file, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRead(t *testing.T) {
	cases := []struct {
		name   string
		cgroup string
		files  map[string]string
		want   int64
	}{
		{"container on v2", "0::/\n", map[string]string{"memory.max": "1073741824\n"}, 1 << 30},
		{"no limit on v2", "0::/\n", map[string]string{"memory.max": "max\n"}, 0},
		{"host without a limit", "0::/user.slice/user-1000.slice/session-1.scope\n", map[string]string{}, 0},
		{"systemd unit's MemoryMax", "0::/system.slice/deaconguard-server.service\n",
			map[string]string{"system.slice/deaconguard-server.service/memory.max": "805306368\n", "system.slice/memory.max": "max\n"}, 768 << 20},
		{"a parent's lower limit", "0::/kubepods/pod1/c1\n",
			map[string]string{"kubepods/pod1/c1/memory.max": "max\n", "kubepods/pod1/memory.max": "536870912\n", "kubepods/memory.max": "8589934592\n"}, 512 << 20},
		{"container on v1", "12:memory:/\n11:cpu,cpuacct:/\n", map[string]string{"memory/memory.limit_in_bytes": "2147483648\n"}, 2 << 30},
		{"no limit on v1", "12:memory:/\n", map[string]string{"memory/memory.limit_in_bytes": "9223372036854771712\n"}, 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, "self"), test.cgroup)
			for name, contents := range test.files {
				write(t, filepath.Join(dir, "cg", name), contents)
			}
			if got := read(filepath.Join(dir, "self"), filepath.Join(dir, "cg")); got != test.want {
				t.Fatalf("read = %d, want %d", got, test.want)
			}
		})
	}
	if got := read(filepath.Join(t.TempDir(), "missing"), "/nowhere"); got != 0 {
		t.Fatalf("without /proc/self/cgroup: %d", got)
	}
}
