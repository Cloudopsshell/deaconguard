package scan

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/advisory"
	"deaconguard/internal/checks"
	"deaconguard/internal/containers"
	"deaconguard/internal/lifecycle"
	"deaconguard/internal/scanner"
)

func TestEvaluateContainers(t *testing.T) {
	calls := 0
	scanPackages = func(osRelease, dpkg, rpm, apk, kernel string, _ *http.Client, _ time.Time) (scanner.Report, error) {
		calls++
		if strings.Contains(osRelease, "ID=gentoo") {
			return scanner.Report{}, errors.New("unsupported Linux distribution \"gentoo\"")
		}
		if kernel != "6.8.0-45-generic" {
			t.Errorf("kernel = %q, want the host's", kernel)
		}
		return scanner.Report{OS: "Debian 12 (bookworm)", PackageCount: 90,
			Lifecycle: lifecycle.Lifecycle{State: lifecycle.Supported},
			Findings: []advisory.Finding{
				{ID: "CVE-2024-1", Package: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.13-1", Severity: "high", Fix: advisory.FixAvailable},
				{ID: "CVE-2024-2", Package: "zlib", InstalledVersion: "1.2", Severity: "critical", Fix: advisory.FixNone, Exploit: &advisory.Exploit{KEV: true}},
				{ID: "CVE-2024-3", Package: "perl", InstalledVersion: "5.36", Severity: "low", Fix: advisory.FixNone},
			}}, nil
	}
	defer func() { scanPackages = scanner.Scan }()
	debian := containers.Inventory{OSRelease: "ID=debian\nVERSION_ID=12\n", DPKGStatus: "Package: openssl\n"}
	gentoo := containers.Inventory{OSRelease: "ID=gentoo\n", DPKGStatus: "Package: x\n", Notes: []string{"a note"}}
	result := checks.Result{Status: checks.StatusCompleted, Containers: []checks.ContainerResult{
		{Container: containers.Container{Name: "web-1", Image: "acme/web:1"}, Inventory: &debian, HostKernel: "6.8.0-45-generic"},
		{Container: containers.Container{Name: "web-2", Image: "acme/web:1"}, Inventory: &debian, HostKernel: "6.8.0-45-generic"},
		{Container: containers.Container{Name: "build", Image: "gentoo:latest"}, Inventory: &gentoo, HostKernel: "6.8.0-45-generic"},
	}}
	evaluateContainers(&result, &reporter{})
	if calls != 2 {
		t.Errorf("package scans = %d, want 2 (web-1 and web-2 have the same contents)", calls)
	}
	web1, web2, build := result.Containers[0], result.Containers[1], result.Containers[2]
	if web1.Inventory != nil {
		t.Error("the raw inventory must be dropped after evaluation")
	}
	if web1.OS != "Debian 12 (bookworm)" || web1.Packages != 90 || web1.Severity["HIGH"] != 1 || web1.Severity["LOW"] != 1 ||
		web1.Exploited != 1 || web1.Fixable != 1 || len(web1.Findings) != 2 {
		t.Errorf("web-1 = %+v", web1)
	}
	if web1.Findings[0].Rule != "CVE-2024-2" || !strings.Contains(web1.Findings[0].Detail, "Known to be exploited") {
		t.Errorf("exploited first: %+v", web1.Findings[0])
	}
	if !strings.HasPrefix(web2.Findings[0].Title, "web-2: ") || web2.Exploited != 1 {
		t.Errorf("web-2 keeps its own name: %+v", web2.Findings[0])
	}
	if !strings.Contains(build.Error, "gentoo") || len(build.Notes) != 1 {
		t.Errorf("build = %+v", build)
	}
	if len(result.Findings) != 4 || !strings.HasPrefix(result.Summary, "3 running containers: 6 vulnerabilities, 4 to fix in 2 containers, 2 known to be exploited") {
		t.Errorf("summary %q, %d findings", result.Summary, len(result.Findings))
	}
}
