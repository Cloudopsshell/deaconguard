package updates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, test := range []struct {
		current, latest string
		want            bool
	}{
		{"1.33.1", "1.34.0", true},
		{"1.29.0", "1.33.1", true},
		{"1.34.0", "1.34.0", false},
		{"1.34.1", "1.34.0", false},
		{"1.34.0-rc.1", "1.34.0", true},
		{"1.34.0-rc.1", "1.33.1", false},
		{"1.9.0", "1.10.0", true},
		{"dev", "1.34.0", false},
		{"1.34.0-dev", "1.35.0", false},
		{"1.33.1-3-gabc1234-dirty", "1.34.0", false},
		{"1.33.1", "1.34.0-rc.1", false},
		{"1.33.1", "", false},
		{"1.33.1", "latest", false},
	} {
		if got := Newer(test.current, test.latest); got != test.want {
			t.Errorf("Newer(%q, %q) = %t, want %t", test.current, test.latest, got, test.want)
		}
	}
}

func TestLatest(t *testing.T) {
	var agent, path string
	answer, status := "1.34.0\n", http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent, path = r.Header.Get("User-Agent"), r.URL.RequestURI()
		if status == http.StatusFound {
			http.Redirect(w, r, "/elsewhere", status)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()

	version, err := Latest(context.Background(), server.URL+"/stable.txt")
	if err != nil || version != "1.34.0" {
		t.Fatalf("Latest = %q, %v", version, err)
	}
	// Nothing about the server that asks is in the request.
	if agent != "DeaconGuard" || path != "/stable.txt" {
		t.Errorf("the request had User-Agent %q and path %q", agent, path)
	}

	answer = "v1.35.2"
	if version, err := Latest(context.Background(), server.URL); err != nil || version != "1.35.2" {
		t.Errorf("with a v prefix: %q, %v", version, err)
	}
	for _, bad := range []string{"", "1.34", "1.34.0-rc.1", "<html>not found</html>", "1.34.0\n1.35.0", strings.Repeat("1", 200)} {
		answer = bad
		if version, err := Latest(context.Background(), server.URL); err == nil {
			t.Errorf("answer %q gave %q, want an error", bad, version)
		}
	}
	answer, status = "1.34.0", http.StatusNotFound
	if _, err := Latest(context.Background(), server.URL); err == nil {
		t.Error("a 404 gave no error")
	}
	status = http.StatusFound
	if _, err := Latest(context.Background(), server.URL); err == nil {
		t.Error("a redirect was followed")
	}
}
