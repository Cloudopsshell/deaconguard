package server

import (
	"net/http/httptest"
	"testing"
)

func TestRemoteIPBehindTrustedProxies(t *testing.T) {
	t.Cleanup(func() { _ = SetTrustedProxies(nil) })
	request := func(remote string, forwarded ...string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, value := range forwarded {
			r.Header.Add("X-Forwarded-For", value)
		}
		return remoteIP(r)
	}
	if err := SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	if got := request("203.0.113.9:5000", "198.51.100.1"); got != "203.0.113.9" {
		t.Fatalf("without trusted proxies the header counts: %s", got)
	}
	if err := SetTrustedProxies([]string{"10.42.0.0/16", " 192.0.2.7 "}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		remote    string
		forwarded []string
		want      string
	}{
		{"10.42.1.5:4000", []string{"198.51.100.1"}, "198.51.100.1"},
		// A client can't hide behind an address it adds itself.
		{"10.42.1.5:4000", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1"},
		{"10.42.1.5:4000", []string{"198.51.100.1, 192.0.2.7"}, "198.51.100.1"},
		{"10.42.1.5:4000", []string{"198.51.100.1", "10.42.0.9"}, "198.51.100.1"},
		{"10.42.1.5:4000", nil, "10.42.1.5"},
		{"10.42.1.5:4000", []string{"not-an-address"}, "10.42.1.5"},
		{"[::ffff:10.42.1.5]:4000", []string{"2001:db8::1"}, "2001:db8::1"},
		// Only trusted proxies are believed.
		{"203.0.113.9:5000", []string{"198.51.100.1"}, "203.0.113.9"},
	} {
		if got := request(test.remote, test.forwarded...); got != test.want {
			t.Errorf("%s with %q: %s, want %s", test.remote, test.forwarded, got, test.want)
		}
	}
	if err := SetTrustedProxies([]string{"10.0.0.0/33"}); err == nil {
		t.Fatal("a bad network was accepted")
	}
}
