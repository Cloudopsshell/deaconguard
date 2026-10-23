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

// Every vulnerability is kept with what the dashboard groups it by, and a
// stopped container is listed without being checked.
func TestEvaluateContainersKeepsEveryVulnerability(t *testing.T) {
	scanPackages = func(_, _, _, _, _ string, _ *http.Client, _ time.Time) (scanner.Report, error) {
		return scanner.Report{OS: "Debian 10 (buster)", PackageCount: 104, Findings: []advisory.Finding{
			{ID: "CVE-2022-2068", Package: "openssl", InstalledVersion: "1.1.1n-0+deb10u3", FixedVersion: "1.1.1n-0+deb10u6", Severity: "critical", Fix: advisory.FixAvailable, Title: "c_rehash command injection"},
			{ID: "CVE-2024-3", Package: "perl", InstalledVersion: "5.28", Severity: "low", Fix: advisory.FixNone},
		}}, nil
	}
	defer func() { scanPackages = scanner.Scan }()
	debian := containers.Inventory{OSRelease: "ID=debian\nVERSION_ID=10\n", DPKGStatus: "Package: openssl\n"}
	result := checks.Result{Status: checks.StatusCompleted, Containers: []checks.ContainerResult{
		{Container: containers.Container{Name: "web-1", Image: "nginx:1.18", State: "running"}, Inventory: &debian},
		{Container: containers.Container{Name: "web-2", Image: "nginx:1.18", State: "running"}, Inventory: &debian},
		{Container: containers.Container{Name: "old-job", Image: "alpine:3.12", State: "exited", ExitCode: 3}},
	}}
	evaluateContainers(&result, &reporter{})
	web1, web2, old := result.Containers[0], result.Containers[1], result.Containers[2]
	if len(web1.Vulnerabilities) != 2 || len(web1.Findings) != 1 {
		t.Fatalf("web-1 keeps every vulnerability and the ones to fix: %+v", web1)
	}
	first := web1.Vulnerabilities[0]
	if first.Source != "os" || first.Package != "openssl" || first.Version != "1.1.1n-0+deb10u3" || first.Fixed != "1.1.1n-0+deb10u6" ||
		!first.Fixable || first.Container != "web-1" || first.Image != "nginx:1.18" || first.Summary != "c_rehash command injection" {
		t.Errorf("first = %+v", first)
	}
	if web1.Vulnerabilities[1].Fixable || web1.Vulnerabilities[1].Fixed != "" {
		t.Errorf("no fix: %+v", web1.Vulnerabilities[1])
	}
	if len(web2.Vulnerabilities) != 2 || web2.Vulnerabilities[0].Container != "web-2" || !strings.HasPrefix(web2.Vulnerabilities[0].Title, "web-2: ") {
		t.Errorf("web-2 = %+v", web2.Vulnerabilities)
	}
	if old.Error != "" || len(old.Vulnerabilities) != 0 || old.Scanned() {
		t.Errorf("stopped container = %+v", old)
	}
	if !strings.HasPrefix(result.Summary, "3 containers, 2 running: 4 vulnerabilities, 2 to fix in 2 containers") {
		t.Errorf("summary = %q", result.Summary)
	}
}

// A container on an ended release gets an end-of-life finding instead of an
// error; one whose packages couldn't be checked makes the check partial.
func TestEvaluateContainersEndOfLifeAndPartial(t *testing.T) {
	scanPackages = func(osRelease, _, _, _, _ string, _ *http.Client, _ time.Time) (scanner.Report, error) {
		if strings.Contains(osRelease, "VERSION_ID=10") {
			return scanner.Report{}, errors.New(`unsupported Debian release "10"`)
		}
		return scanner.Report{}, errors.New("advisory feed unavailable")
	}
	defer func() { scanPackages = scanner.Scan }()
	buster := containers.Inventory{OSRelease: "ID=debian\nVERSION_ID=10\nVERSION_CODENAME=buster\n",
		DPKGStatus: "Package: openssl\nVersion: 1\n\nPackage: zlib1g\nVersion: 1\n\n"}
	bookworm := containers.Inventory{OSRelease: "ID=debian\nVERSION_ID=12\n", DPKGStatus: "Package: openssl\n"}
	result := checks.Result{Status: checks.StatusCompleted, Containers: []checks.ContainerResult{
		{Container: containers.Container{Name: "web", Image: "nginx:1.18", State: "running"}, Inventory: &buster},
	}}
	evaluateContainers(&result, &reporter{})
	web := result.Containers[0]
	if web.Error != "" || web.OS != "Debian 10 (buster)" || web.Lifecycle == nil || web.Lifecycle.State != lifecycle.Ended || web.Packages != 2 {
		t.Fatalf("web = %+v", web)
	}
	if len(web.Vulnerabilities) != 1 || web.Severity["HIGH"] != 1 || web.Fixable != 1 || len(web.Findings) != 1 {
		t.Fatalf("an end-of-life finding to fix: %+v", web)
	}
	eol := web.Vulnerabilities[0]
	if eol.Rule != EndOfLifeRule || eol.Source != "os" || eol.Package != "debian" || eol.Version != "10 (buster)" || !eol.Fixable ||
		eol.Fixed == "" || !strings.Contains(eol.Detail, "reached end of life on 30 June 2024") || eol.Container != "web" {
		t.Errorf("finding = %+v", eol)
	}
	if result.Status != checks.StatusCompleted {
		t.Errorf("an end-of-life container was fully checked: status %s", result.Status)
	}

	result = checks.Result{Status: checks.StatusCompleted, Containers: []checks.ContainerResult{
		{Container: containers.Container{Name: "api", Image: "python:3.11", State: "running"}, Inventory: &bookworm},
	}}
	evaluateContainers(&result, &reporter{})
	if result.Status != checks.StatusPartial || !strings.Contains(result.Summary, "1 couldn't be fully checked") || result.Containers[0].Error == "" {
		t.Errorf("unchecked packages must not look clean: %s, %q, %+v", result.Status, result.Summary, result.Containers[0])
	}
}
