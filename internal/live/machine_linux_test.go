//go:build linux

package live

import "testing"

func TestTCPAddress(t *testing.T) {
	cases := map[string]string{
		"0100007F:1F90":                         "127.0.0.1:8080",
		"097100CB:2329":                         "203.0.113.9:9001",
		"B80D0120000000000000000001000000:0016": "[2001:db8::1]:22",
		"0000000000000000FFFF0000097100CB:2329": "203.0.113.9:9001",
		"zz:1":                                  "",
	}
	for text, want := range cases {
		if got := tcpAddress(text); got != want {
			t.Errorf("%s: %q, want %q", text, got, want)
		}
	}
}
