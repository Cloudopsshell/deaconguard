package scanner

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func response(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestScanDebianBookwormUsesOfficialTrackerAndDPKGInventory(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "security-tracker.debian.org" {
			t.Fatalf("unexpected feed host: %s", request.URL.Host)
		}
		return response(`{"example":{"CVE-2025-0001":{"description":"Debian integration issue","releases":{"bookworm":{"status":"resolved","fixed_version":"1.0-2","urgency":"high"}}}}}`), nil
	})}
	status := "Package: example\nStatus: install ok installed\nVersion: 1.0-1\nSource: example\n\n"
	report, err := Scan("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n", status, "", "6.1.0", client, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.OS != "Debian 12 (bookworm)" || report.PackageManager != "dpkg" || report.FindingCount != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Findings[0].FixedVersion != "1.0-2" || report.AdvisoryDatabase.Source != "https://security-tracker.debian.org/tracker/data/json" {
		t.Fatalf("unexpected advisory result: %+v", report.Findings[0])
	}
}

func TestScanAmazonLinux2023UsesALASAndRPMInventory(t *testing.T) {
	t.Setenv("OPSARMOR_HOME", t.TempDir())
	const advisoryURL = "https://alas.aws.amazon.com/AL2023/ALAS2023-2026-100.html"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case "https://alas.aws.amazon.com/AL2023/alas.rss":
			return response(`<rss><channel><item><title>ALAS2023-2026-100 (Important): example-source</title><description>CVE-2026-12345</description><link>` + advisoryURL + `</link></item></channel></rss>`), nil
		case advisoryURL:
			return response(`<html><body><div id="new_packages"><pre>x86_64:<br/> example-1.0-2.amzn2023.0.1.x86_64</pre></div></body></html>`), nil
		default:
			t.Fatalf("unexpected advisory URL: %s", request.URL)
			return nil, nil
		}
	})}
	rpmQuery := "example\t0\t1.0\t1.amzn2023.0.1\texample-source-1.0-1.amzn2023.0.1.src.rpm\tx86_64\n"
	report, err := Scan("ID=amzn\nVERSION_ID=2023\nNAME=Amazon Linux\n", "", rpmQuery, "6.1.0-aws", client, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.OS != "Amazon Linux 2023" || report.PackageManager != "rpm" || report.FindingCount != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Findings[0].ID != "CVE-2026-12345" || report.Findings[0].FixedVersion != "1.0-2.amzn2023.0.1" {
		t.Fatalf("unexpected ALAS result: %+v", report.Findings[0])
	}
}

func TestScanRejectsCentOSStreamBeforeAdvisoryLookup(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported CentOS Stream must not query RHEL or another vendor feed")
		return nil, nil
	})}
	_, err := Scan("NAME=CentOS Stream\nID=centos\nVERSION_ID=10\n", "", "", "6.1.0", client, time.Now())
	if err == nil || !strings.Contains(err.Error(), "no authoritative advisory feed") {
		t.Fatalf("unexpected CentOS Stream result: %v", err)
	}
}
