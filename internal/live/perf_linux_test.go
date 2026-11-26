//go:build linux

package live

import (
	"bytes"
	"testing"
)

func TestPerfBufferSize(t *testing.T) {
	for _, c := range []struct{ cpus, want int }{{1, 256 << 10}, {2, 128 << 10}, {4, 64 << 10}, {8, 32 << 10}, {64, 32 << 10}} {
		if got := perfBufferSize(c.cpus, 4096); got != c.want {
			t.Errorf("%d CPUs: %d, want %d", c.cpus, got, c.want)
		}
	}
}

// A record that wraps around the end of a CPU's buffer reads as one piece.
func TestPerfCopyWraps(t *testing.T) {
	p := &perfBuffers{size: 16}
	data := []byte("0123456789abcdef")
	if got := p.copy(data, 4, 8); string(got) != "456789ab" {
		t.Fatalf("inside: %q", got)
	}
	if got := p.copy(data, 12+16, 8); !bytes.Equal(got, []byte("cdef0123")) {
		t.Fatalf("wrapped: %q", got)
	}
}

func TestSupportedKernel(t *testing.T) {
	for release, want := range map[string]bool{
		"6.8.0-45-generic": true, "5.4.0-216-generic": true, "4.19.0-21-amd64": true,
		"4.18.0-553.el8_10.x86_64": true, "4.17.0": false, "4.14.355-275.amzn2.x86_64": false,
		"3.10.0-1160.el7.x86_64": false, "": false,
	} {
		if got := supportedKernel(release); got != want {
			t.Errorf("%q: %v, want %v", release, got, want)
		}
	}
	if !releaseAtLeast("5.11.0", 5, 11) || releaseAtLeast("5.10.0", 5, 11) {
		t.Error("releaseAtLeast")
	}
}
