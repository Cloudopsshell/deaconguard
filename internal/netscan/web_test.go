package netscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// careless serves what a site should never publish, and none of the
// headers it should send.
func careless() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.2.24")
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>Index of /</title></html>"))
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ref: refs/heads/main\n")) })
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"))
	})
	mux.HandleFunc("/info.php", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><title>phpinfo()</title><h1>PHP Version 7.2.24</h1></html>"))
	})
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"activeProfiles":[],"propertySources":[{"name":"server.ports"}]}`))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines 8\n"))
	})
	return mux
}

// careful sends the headers a site should, and answers every path with its
// home page, as single-page apps do.
func careful() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!doctype html><html><title>Shop</title><body>KEY=value\nOTHER=value\nref: refs/heads/main</body></html>"))
	})
}

func check(t *testing.T, server *httptest.Server, options WebOptions) (WebInfo, []string) {
	t.Helper()
	site, _ := url.Parse(server.URL)
	options.Timeout = 2 * time.Second
	info, findings, err := CheckWeb(context.Background(), site, options)
	if err != nil {
		t.Fatal(err)
	}
	return info, rules(findings)
}

func TestCarelessSiteIsReported(t *testing.T) {
	server := httptest.NewTLSServer(careless())
	defer server.Close()
	info, found := check(t, server, WebOptions{Paths: true})
	for _, want := range []string{"DG-WEB-001", "DG-WEB-002", "DG-WEB-004", "DG-WEB-005", "DG-WEB-006", "DG-WEB-007", "DG-WEB-009",
		"DG-WEB-010", "DG-WEB-011", "DG-WEB-012", "DG-WEB-013", "DG-WEB-014", "DG-WEB-015", "DG-WEB-016"} {
		if !slices.Contains(found, want) {
			t.Errorf("%s not reported: %v", want, found)
		}
	}
	if slices.Contains(found, "DG-WEB-003") || slices.Contains(found, "DG-WEB-008") {
		t.Errorf("reported what isn't there: %v", found)
	}
	if info.Status != 200 || info.Server != "Apache/2.4.29 (Ubuntu)" || info.Requests > 15 {
		t.Errorf("info %+v", info)
	}
	// Without paths, only the home page is read.
	info, found = check(t, server, WebOptions{})
	if slices.Contains(found, "DG-WEB-001") || info.Requests != 2 {
		t.Errorf("without paths: %d requests, %v", info.Requests, found)
	}
}

func TestCarefulSiteIsClean(t *testing.T) {
	server := httptest.NewTLSServer(careful())
	defer server.Close()
	if _, found := check(t, server, WebOptions{Paths: true}); len(found) != 0 {
		t.Errorf("a careful site that answers every path got %v", found)
	}
}

func TestPlainHTTP(t *testing.T) {
	plain := httptest.NewServer(careful())
	defer plain.Close()
	if _, found := check(t, plain, WebOptions{HTTPS: true}); !slices.Contains(found, "DG-WEB-008") {
		t.Errorf("plain HTTP beside HTTPS: %v", found)
	}
	if _, found := check(t, plain, WebOptions{}); slices.Contains(found, "DG-WEB-008") {
		t.Errorf("plain HTTP with no HTTPS to go to: %v", found)
	}
	redirect := httptest.NewServer(http.RedirectHandler("https://www.example.com/", http.StatusMovedPermanently))
	defer redirect.Close()
	if _, found := check(t, redirect, WebOptions{HTTPS: true, Paths: true}); len(found) != 0 {
		t.Errorf("a redirect to HTTPS elsewhere: %v", found)
	}
}

func TestWebSitesAndURLs(t *testing.T) {
	host := Host{Address: "10.0.0.4", Name: "shop.example.com", Services: []Service{
		{Port: 22, Name: "SSH"}, {Port: 80, Name: "HTTP"}, {Port: 443, Name: "HTTPS", TLS: true}, {Port: 8080, Name: "HTTP (alt)"},
		{Port: 6443, Name: "Kubernetes API", TLS: true},
	}}
	var got []string
	for _, site := range webSites(host) {
		got = append(got, site.String())
	}
	if !slices.Equal(got, []string{"http://shop.example.com", "https://shop.example.com", "http://shop.example.com:8080"}) || !servesHTTPS(host) {
		t.Errorf("sites %v", got)
	}
	for raw, want := range map[string]string{"shop.example.com": "https://shop.example.com", "http://10.0.0.4:8080/x?y": "http://10.0.0.4:8080"} {
		if site, err := SiteURL(raw); err != nil || site.String() != want {
			t.Errorf("SiteURL(%q) = %v, %v", raw, site, err)
		}
	}
	for _, bad := range []string{"ftp://x", "https://", "::"} {
		if _, err := SiteURL(bad); err == nil || !strings.Contains(err.Error(), "web address") {
			t.Errorf("SiteURL(%q) accepted", bad)
		}
	}
}
