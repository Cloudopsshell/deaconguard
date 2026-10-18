package osv

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/libraries"
)

func TestCVSS3BaseScore(t *testing.T) {
	for vector, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, ok := cvss3BaseScore(vector)
		if !ok || got != want {
			t.Errorf("cvss3BaseScore(%s) = %v, %v; want %v", vector, got, ok, want)
		}
	}
	for _, bad := range []string{"CVSS:4.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "garbage"} {
		if _, ok := cvss3BaseScore(bad); ok {
			t.Errorf("cvss3BaseScore(%s) accepted", bad)
		}
	}
}

// fakeOSV answers like api.osv.dev for lodash 4.17.20 and requests 2.25.1.
func fakeOSV(t *testing.T, queries *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			queries.Add(1)
			var body struct {
				Queries []query `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode query: %v", err)
			}
			results := make([]map[string]any, len(body.Queries))
			for index, q := range body.Queries {
				results[index] = map[string]any{}
				if strings.Contains(q.Package.Name, "/") || q.Version == "" {
					t.Errorf("unexpected query %+v", q)
				}
				switch q.Package.Name + "@" + q.Version {
				case "lodash@4.17.20":
					results[index] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-35jh-r3h4-6jhm"}}}
				case "requests@2.25.1":
					results[index] = map[string]any{"vulns": []map[string]string{{"id": "PYSEC-2023-74"}, {"id": "GHSA-j8r2-6x86-q33q"}}, "next_page_token": "p2"}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/query":
			json.NewEncoder(w).Encode(map[string]any{"vulns": []map[string]string{{"id": "GHSA-withdrawn"}}})
		case r.URL.Path == "/v1/vulns/GHSA-35jh-r3h4-6jhm":
			w.Write([]byte(`{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","aliases":["CVE-2021-23337"],
				"database_specific":{"severity":"HIGH"},
				"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
		case r.URL.Path == "/v1/vulns/PYSEC-2023-74":
			w.Write([]byte(`{"id":"PYSEC-2023-74","summary":"","aliases":["CVE-2023-32681","GHSA-j8r2-6x86-q33q"],
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"}],
				"affected":[{"package":{"ecosystem":"PyPI","name":"Requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.3.0"},{"fixed":"2.31.0"}]}]}]}`))
		case r.URL.Path == "/v1/vulns/GHSA-j8r2-6x86-q33q":
			w.Write([]byte(`{"id":"GHSA-j8r2-6x86-q33q","summary":"Unintended leak of Proxy-Authorization header in requests","aliases":["CVE-2023-32681","PYSEC-2023-74"],
				"database_specific":{"severity":"MODERATE"},
				"affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.3.0"},{"fixed":"2.31.0"}]}]}]}`))
		case r.URL.Path == "/v1/vulns/GHSA-withdrawn":
			w.Write([]byte(`{"id":"GHSA-withdrawn","withdrawn":"2024-01-01T00:00:00Z","summary":"withdrawn"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

type noNetwork struct{}

func (noNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests")
}

func testClient(t *testing.T, server *httptest.Server) *Client {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	return &Client{HTTP: server.Client(), BaseURL: server.URL, CacheDir: t.TempDir(), Now: time.Now}
}

func TestEvaluate(t *testing.T) {
	var queries atomic.Int32
	server := fakeOSV(t, &queries)
	defer server.Close()
	client := testClient(t, server)
	result := checks.Result{Status: checks.StatusCompleted, Findings: []checks.Finding{{Rule: "agent-made-this-up"}},
		Libraries: &libraries.Result{Libraries: []libraries.Library{
			{Ecosystem: libraries.NPM, Name: "lodash", Version: "4.17.20", Paths: []string{"/srv/app/package-lock.json"}},
			{Ecosystem: libraries.PyPI, Name: "requests", Version: "2.25.1", Paths: []string{"/opt/venv/x/METADATA"}},
			{Ecosystem: libraries.NPM, Name: "left-pad", Version: "1.3.0", Paths: []string{"/srv/app/package-lock.json"}},
		}}}
	Evaluate(&result, client, noNetwork{}, time.Now())
	if result.Status != checks.StatusCompleted {
		t.Fatalf("status = %s (%s), want completed", result.Status, result.Error)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2 (the agent's own and the withdrawn one dropped)", result.Findings)
	}
	lodash, requests := result.Findings[0], result.Findings[1]
	if lodash.Rule != "GHSA-35jh-r3h4-6jhm" || lodash.Severity != "HIGH" ||
		!strings.Contains(lodash.Title, "lodash 4.17.20 (npm): Command Injection") ||
		!strings.Contains(lodash.Detail, "CVE-2021-23337.") || !strings.Contains(lodash.Detail, "Fixed in 4.17.21.") ||
		lodash.Evidence != "/srv/app/package-lock.json" {
		t.Errorf("lodash finding = %+v", lodash)
	}
	// PYSEC-2023-74 and GHSA-j8r2-6x86-q33q are one vulnerability: one finding,
	// shown with the GitHub advisory's summary.
	if requests.Rule != "GHSA-j8r2-6x86-q33q" || requests.Severity != "MEDIUM" || !strings.Contains(requests.Detail, "Fixed in 2.31.0.") ||
		!strings.Contains(requests.Title, "requests 2.25.1 (PyPI): Unintended leak of Proxy-Authorization header") || !strings.Contains(requests.Detail, "CVE-2023-32681.") {
		t.Errorf("requests finding = %+v", requests)
	}
	if result.Summary != "2 vulnerabilities in 2 of 3 libraries" {
		t.Errorf("summary = %q", result.Summary)
	}

	// A second scan within a day uses the cached records.
	server.Close()
	cachedOnly := &Client{HTTP: noNetwork{}, BaseURL: "http://unreachable", CacheDir: client.CacheDir, Now: time.Now}
	records, err := cachedOnly.Records(t.Context(), []string{"GHSA-35jh-r3h4-6jhm"})
	if err != nil || records["GHSA-35jh-r3h4-6jhm"].Summary == "" {
		t.Errorf("cached record: %v, %v", records, err)
	}
}

func TestTitleFromDetails(t *testing.T) {
	got := title(libraries.Library{Ecosystem: libraries.PyPI, Name: "idna", Version: "2.10"}, Vulnerability{ID: "PYSEC-2024-60", Details: "Denial of service in idna.encode()\n\nMore text."})
	if got != "idna 2.10 (PyPI): Denial of service in idna.encode()" {
		t.Errorf("title = %q", got)
	}
}

func TestEvaluateFailsWhenOSVIsUnreachable(t *testing.T) {
	t.Setenv("DEACONGUARD_HOME", t.TempDir())
	client := &Client{HTTP: noNetwork{}, BaseURL: "http://unreachable", CacheDir: t.TempDir(), Now: time.Now}
	result := checks.Result{Libraries: &libraries.Result{Libraries: []libraries.Library{{Ecosystem: libraries.NPM, Name: "lodash", Version: "4.17.20"}}}}
	Evaluate(&result, client, noNetwork{}, time.Now())
	if result.Status != checks.StatusFailed || !strings.Contains(result.Error, "OSV") || len(result.Findings) != 0 {
		t.Errorf("result = %+v; an unreachable OSV must fail the check, never look clean", result)
	}
}

func TestEvaluateWithoutLibraryList(t *testing.T) {
	result := checks.Result{Status: checks.StatusCompleted}
	Evaluate(&result, &Client{}, noNetwork{}, time.Now())
	if result.Status != checks.StatusFailed {
		t.Errorf("status = %s, want failed", result.Status)
	}
}

func TestBatchesOfAThousand(t *testing.T) {
	var queries atomic.Int32
	server := fakeOSV(t, &queries)
	defer server.Close()
	client := testClient(t, server)
	libs := make([]libraries.Library, 2500)
	for index := range libs {
		libs[index] = libraries.Library{Ecosystem: libraries.NPM, Name: "pkg", Version: "1.0." + strings.Repeat("1", index%3+1)}
	}
	if _, err := client.Query(t.Context(), libs); err != nil {
		t.Fatal(err)
	}
	if queries.Load() != 3 {
		t.Errorf("batch requests = %d, want 3", queries.Load())
	}
}
