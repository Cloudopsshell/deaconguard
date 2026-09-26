package advisory

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"opsarmor/internal/inventory"
	"opsarmor/internal/platform"
)

func TestEvaluateAmazonLinux2023UsesALASReplacementPackage(t *testing.T) {
	rss := []byte(`<rss><channel><item>
  <title>ALAS2023-2026-100 (Important): example-source</title>
  <description>CVE-2026-12345</description>
  <link>https://alas.aws.amazon.com/AL2023/ALAS2023-2026-100.html</link>
</item></channel></rss>`)
	bulletin := []byte(`<html><body>
  <div id="affected_packages"><p>example-source</p></div>
  <div id="new_packages"><pre>x86_64:<br/> example-1.2-3.amzn2023.0.2.x86_64<br/> noarch:<br/> example-doc-1.2-3.amzn2023.0.2.noarch</pre></div>
</body></html>`)
	packages := []inventory.Package{{
		Name: "example", Version: "1.2-3.amzn2023.0.1", Source: "example-source", Arch: "x86_64",
	}}
	result, err := evaluateAmazonLinux2023RSS(
		context.Background(), packages, rss,
		func(context.Context, string) ([]byte, error) { return bulletin, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evaluated != 1 || len(result.Findings) != 1 {
		t.Fatalf("unexpected ALAS evaluation: %+v", result)
	}
	finding := result.Findings[0]
	if finding.ID != "CVE-2026-12345" || finding.FixedVersion != "1.2-3.amzn2023.0.2" || finding.Severity != "HIGH" {
		t.Fatalf("unexpected ALAS finding: %+v", finding)
	}
}

func TestEvaluateAmazonLinux2023SurfacesMissingReplacementPackage(t *testing.T) {
	rss := []byte(`<rss><channel><item><title>ALAS2023-2026-101 (Low): example-source</title><description>CVE-2026-12346</description><link>https://example.test/advisory</link></item></channel></rss>`)
	packages := []inventory.Package{{Name: "example", Version: "1.0-1", Source: "example-source", Arch: "aarch64"}}
	result, err := evaluateAmazonLinux2023RSS(
		context.Background(), packages, rss,
		func(context.Context, string) ([]byte, error) {
			return []byte(`<div id="new_packages"><pre>example-2.0-1.amzn2023.0.1.x86_64</pre></div>`), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Unsupported) != 1 || result.Unsupported[0].ID != "CVE-2026-12346" {
		t.Fatalf("missing architecture package was not reported as unsupported: %+v", result)
	}
}

func TestALASParserRejectsInvalidFeedAndBulletin(t *testing.T) {
	if _, err := evaluateAmazonLinux2023RSS(
		context.Background(), nil, []byte("not xml"), func(context.Context, string) ([]byte, error) { return nil, nil },
	); err == nil {
		t.Fatal("expected malformed ALAS RSS to fail")
	}
	if _, err := parseALASNewPackages([]byte("<html><body>" + strings.Repeat("x", 2) + "</body></html>")); err == nil {
		t.Fatal("expected bulletin without replacement package data to fail")
	}
}

func TestLoadRedHatOVALOnlyAcceptsVerifiedFeedVersions(t *testing.T) {
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("oval")), Header: make(http.Header)}, nil
	})
	target := platform.Platform{Family: platform.RHEL, Major: 9}
	feed, err := LoadRedHatOVAL(target, client, time.Now())
	if err != nil || feed.Metadata.Source != "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2" {
		t.Fatalf("unexpected RHEL feed: %+v, %v", feed.Metadata, err)
	}
	if _, err := LoadRedHatOVAL(platform.Platform{Family: platform.RHEL, Major: 10}, client, time.Now()); err == nil {
		t.Fatal("RHEL 10 without an official OVAL feed should not be accepted")
	}
}
