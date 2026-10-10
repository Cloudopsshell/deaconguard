package checks

import (
	"fmt"
	"strings"
	"time"
)

const (
	antivirusTimeout = 45 * time.Minute
	// Signatures older than this miss recent malware.
	maxSignatureAge = 7 * 24 * time.Hour
	// clamscan holds its whole signature database in memory. Below this much
	// available memory and swap, the kernel may kill it or other services.
	minClamMemoryKB = 1536 * 1024
)

const (
	clamDetectCommand  = "command -v clamscan 2>/dev/null; true"
	clamVersionCommand = "clamscan --version 2>/dev/null"
	memInfoCommand     = "grep -E '^(MemAvailable|SwapFree):' /proc/meminfo"
	// Scans the directories where dropped tools and web shells usually live,
	// at the lowest CPU priority. Missing directories are skipped.
	clamScanCommand = `dirs=""; for d in /tmp /var/tmp /dev/shm /home /root /opt /usr/local /var/www /srv; do [ -d "$d" ] && dirs="$dirs $d"; done; ` +
		`nice -n 19 clamscan --recursive --infected --no-summary --stdout --max-filesize=50M --max-scansize=200M --cross-fs=no $dirs 2>/dev/null`
)

func runAntivirus(executor *Executor, now time.Time) Result {
	output, _, err := executor.Run(clamDetectCommand, 4096, time.Minute)
	if err != nil {
		return failed(fmt.Errorf("look for ClamAV: %w", err))
	}
	if strings.TrimSpace(string(output)) == "" {
		return Result{
			Status: StatusSkipped, Summary: "ClamAV is not installed on this host",
			Notes:    []string{"The DeaconGuard install script installs ClamAV and keeps its signatures current; run it again to add ClamAV: curl -fsSL https://get.deaconguard.io | sudo sh -"},
			Findings: []Finding{},
		}
	}
	var result Result
	if version, _, err := executor.Run(clamVersionCommand, 4096, time.Minute); err == nil {
		checkSignatureAge(&result, strings.TrimSpace(string(version)), now)
	}
	if meminfo, _, err := executor.Run(memInfoCommand, 4096, time.Minute); err == nil {
		if available, ok := availableMemoryKB(meminfo); ok && available < minClamMemoryKB {
			result.Status = StatusSkipped
			result.Summary = "Not enough free memory to run ClamAV safely"
			result.note("The host has about %d MB of available memory and swap; ClamAV needs about %d MB. Running it could make the kernel "+
				"kill ClamAV or other services. Add memory or swap to enable this check.", available/1024, minClamMemoryKB/1024)
			return result.finish(false)
		}
	}
	output, code, privileged, err := executor.RunPrivileged(clamScanCommand, 4<<20, antivirusTimeout)
	// clamscan exits 1 when it finds malware and 2 when some files could not be read.
	if err != nil && code != 1 && code != 2 {
		return failed(fmt.Errorf("clamscan: %w", err))
	}
	for _, line := range lines(output) {
		file, signature, found := strings.Cut(line, ": ")
		if !found || !strings.HasSuffix(signature, " FOUND") {
			continue
		}
		result.add(Finding{
			Rule: "antivirus.detection", Severity: "CRITICAL", Title: "ClamAV detected " + strings.TrimSuffix(signature, " FOUND"),
			Detail:   "ClamAV matched this file against a malware signature. Isolate the host and investigate how the file arrived before deleting it.",
			Evidence: file,
		})
	}
	partial := code == 2 || !privileged
	if code == 2 {
		result.note("Some files could not be scanned.")
	}
	if !privileged {
		result.note("Without sudo, files that belong to other users and /root were not scanned.")
	}
	result.Privileged = privileged
	return result.finish(partial)
}

// availableMemoryKB adds MemAvailable and SwapFree from /proc/meminfo.
func availableMemoryKB(meminfo []byte) (int, bool) {
	total, found := 0, false
	for _, line := range lines(meminfo) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var value int
		if _, err := fmt.Sscan(fields[1], &value); err == nil {
			total += value
			found = true
		}
	}
	return total, found
}

// checkSignatureAge reads "ClamAV 1.0.7/27410/Tue Sep 23 08:24:02 2025".
func checkSignatureAge(result *Result, version string, now time.Time) {
	parts := strings.SplitN(version, "/", 3)
	if len(parts) != 3 {
		result.note("ClamAV signature date could not be read from %q.", truncate(version, 100))
		return
	}
	updated, err := time.Parse("Mon Jan _2 15:04:05 2006", strings.TrimSpace(parts[2]))
	if err != nil {
		result.note("ClamAV signature date could not be read from %q.", truncate(version, 100))
		return
	}
	if age := now.Sub(updated); age > maxSignatureAge {
		result.add(Finding{
			Rule: "antivirus.stale-signatures", Severity: "MEDIUM",
			Title:    fmt.Sprintf("ClamAV signatures are %d days old", int(age.Hours()/24)),
			Detail:   "Outdated signatures miss recent malware. Run freshclam or enable the clamav-freshclam service.",
			Evidence: version,
		})
	}
}
