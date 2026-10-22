package scanner

import (
	"strings"
	"testing"
	"time"

	"deaconguard/internal/lifecycle"
	"deaconguard/internal/platform"
)

const macOSData = `[{"cycle":"27","codename":"Golden Gate","eol":false,"latest":"27.0.1"},
{"cycle":"26","codename":"Tahoe","eol":false,"latest":"26.7.1"},
{"cycle":"14","codename":"Sonoma","eol":"2026-09-14","latest":"14.8.9"},
{"cycle":"10.15","codename":"Catalina","eol":true,"latest":"10.15.7"}]`

func TestEvaluateMacOS(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	mac := func(version string) platform.Platform {
		release, err := platform.MacOSRelease("ProductName:\tmacOS\nProductVersion:\t" + version + "\nBuildVersion:\t26A1\n")
		if err != nil {
			t.Fatal(err)
		}
		target, err := platform.Detect(release)
		if err != nil {
			t.Fatal(err)
		}
		return target
	}
	findings, life := evaluateMacOS(mac("27.0.1"), "No new software available.", []byte(macOSData), now)
	if len(findings) != 0 || life.State != lifecycle.Supported {
		t.Fatalf("a current Mac: %+v %+v", findings, life)
	}
	findings, life = evaluateMacOS(mac("26.6"), "", []byte(macOSData), now)
	if len(findings) != 1 || findings[0].FixedVersion != "26.7.1" || findings[0].Severity != "HIGH" || life.State != lifecycle.Supported {
		t.Fatalf("a Mac behind: %+v %+v", findings, life)
	}
	_, life = evaluateMacOS(mac("14.8.9"), "", []byte(macOSData), now)
	if life.State != lifecycle.Ended || life.Until != "2026-09-14" {
		t.Fatalf("Sonoma after its end: %+v", life)
	}
	_, life = evaluateMacOS(mac("10.15.7"), "", []byte(macOSData), now)
	if life.State != lifecycle.Ended {
		t.Fatalf("Catalina: %+v", life)
	}
	updates := "Software Update found the following new or updated software:\n" +
		"* Label: macOS Tahoe 26.7.1-25H90\n\tTitle: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 3000000KiB, Recommended: YES, Action: restart,\n" +
		"* Label: Command Line Tools for Xcode-17.0\n\tTitle: Command Line Tools for Xcode, Version: 17.0, Size: 800000KiB, Recommended: YES,\n"
	findings, _ = evaluateMacOS(mac("26.6"), updates, []byte(macOSData), now)
	if len(findings) != 2 || findings[1].Package != "Command Line Tools for Xcode" || findings[1].Severity != "MEDIUM" {
		t.Fatalf("pending updates, with the macOS one counted once: %+v", findings)
	}
	if !strings.Contains(findings[0].Title, "26.7.1") {
		t.Errorf("title: %s", findings[0].Title)
	}
	if _, err := platform.MacOSRelease("ProductName: macOS\nProductVersion: 27.0; rm -rf /\n"); err == nil {
		t.Error("accepted an odd version")
	}
}
