package advisory

import (
	"regexp"
	"strings"

	"deaconguard/internal/inventory"
	"deaconguard/internal/platform"
	"deaconguard/internal/version"
)

// What clears a finding, from the most to the least within your control.
const (
	// FixAvailable: the distribution published a fixed package; installing
	// updates fixes it.
	FixAvailable = "available"
	// FixReboot: the running kernel is vulnerable, and a fixed kernel is
	// already installed; restarting the machine fixes it.
	FixReboot = "reboot"
	// FixOldKernel: an older kernel that is installed but not running, kept
	// as a fallback; removing old kernels clears it.
	FixOldKernel = "old_kernel"
	// FixUbuntuPro: Ubuntu publishes the fix only in Ubuntu Pro (ESM).
	FixUbuntuPro = "ubuntu_pro"
	// FixNone: the distribution has not published a fix yet; updating cannot
	// help until it does.
	FixNone = "none"
)

// FixStates lists every fix state in display order.
var FixStates = []string{FixAvailable, FixReboot, FixOldKernel, FixUbuntuPro, FixNone}

// Actionable reports whether installing updates or restarting fixes a
// finding in this state.
func Actionable(fix string) bool { return fix == FixAvailable || fix == FixReboot }

// runningKernelPackage is the name the Ubuntu evaluator gives findings about
// the running kernel.
const runningKernelPackage = "running kernel"

// debianKernelPackage matches packages built for one kernel ABI, such as
// linux-image-6.1.0-25-amd64 or linux-headers-6.8.0-31-generic; group 1 is
// the ABI.
var debianKernelPackage = regexp.MustCompile(`^linux-(?:image|image-unsigned|modules|modules-extra|headers|objects|buildinfo|tools)-(\d+\.\d+(?:\.\d+)?-\d+)(?:-[a-z0-9.+-]+)?$`)

// kernelABI is the ABI of a running Debian or Ubuntu kernel, such as 6.8.0-31
// for 6.8.0-31-generic.
var kernelABI = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?-\d+)`)

// rpmKernelPackage matches the kernel packages dnf keeps several versions of.
func rpmKernelPackage(name string) bool {
	switch name {
	case "kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-modules-extra",
		"kernel-devel", "kernel-uki-virt", "kernel-livepatch":
		return true
	}
	return strings.HasPrefix(name, "kernel-debug") || strings.HasPrefix(name, "kernel-rt") ||
		strings.HasPrefix(name, "kernel-uek") || strings.HasPrefix(name, "kernel-64k")
}

// Classify sets each finding's Fix: whether updating, restarting, removing
// old kernels, or Ubuntu Pro clears it, or no fix exists yet. kernel is the
// running kernel's release, as uname -r prints it.
func Classify(findings []Finding, family platform.Family, packages []inventory.Package, kernel string) {
	installed := make(map[string][]inventory.Package)
	for _, item := range packages {
		installed[item.Name] = append(installed[item.Name], item)
	}
	for i := range findings {
		findings[i].Fix = classify(findings[i], family, packages, installed, kernel)
	}
}

func classify(finding Finding, family platform.Family, packages []inventory.Package, installed map[string][]inventory.Package, kernel string) string {
	switch family {
	case platform.Ubuntu, platform.Debian:
		if finding.Package == runningKernelPackage {
			if finding.FixedVersion == "" {
				return FixNone
			}
			if fixedKernelInstalled(packages, kernel, finding.FixedVersion) {
				return FixReboot
			}
		} else if match := debianKernelPackage.FindStringSubmatch(finding.Package); match != nil {
			if running := kernelABI.FindString(kernel); running != "" && match[1] != running {
				return FixOldKernel
			}
			if finding.FixedVersion != "" && newerInstalled(packages, finding, version.Debian) {
				return FixReboot
			}
		}
		if finding.FixedVersion == "" {
			return FixNone
		}
		if family == platform.Ubuntu && strings.Contains(finding.FixedVersion, "esm") {
			return FixUbuntuPro
		}
		return FixAvailable
	case platform.RHEL, platform.AmazonLinux:
		if finding.FixedVersion == "" {
			return FixNone
		}
		if rpmKernelPackage(finding.Package) {
			if !runningRPM(installed[finding.Package], finding.InstalledVersion, kernel) {
				return FixOldKernel
			}
			for _, other := range installed[finding.Package] {
				if comparison, err := version.RPM(other.Version, finding.FixedVersion); err == nil && comparison >= 0 {
					return FixReboot
				}
			}
		}
		return FixAvailable
	}
	if finding.FixedVersion == "" {
		return FixNone
	}
	return FixAvailable
}

// fixedKernelInstalled reports whether a kernel image of the running kernel's
// flavour, such as -aws or -generic, is installed at the fixed version or
// later. Ubuntu's fixed versions name the ABI, such as 0:6.8.0-35.
func fixedKernelInstalled(packages []inventory.Package, kernel, fixed string) bool {
	runningABI := kernelABI.FindString(kernel)
	flavour := strings.TrimPrefix(kernel, runningABI)
	fixed = strings.TrimPrefix(fixed, "0:")
	if runningABI == "" {
		return false
	}
	for _, item := range packages {
		release, ok := strings.CutPrefix(item.Name, "linux-image-")
		if !ok {
			release = strings.TrimPrefix(item.Name, "linux-image-unsigned-")
		}
		abi := kernelABI.FindString(release)
		if abi == "" || abi == runningABI || strings.TrimPrefix(release, abi) != flavour {
			continue
		}
		if comparison, err := version.Debian(abi, fixed); err == nil && comparison >= 0 {
			return true
		}
	}
	return false
}

// newerInstalled reports whether another package from the same source, built
// for a newer kernel ABI, is installed at the fixed version or later: the
// fix is installed and waits for a restart.
func newerInstalled(packages []inventory.Package, finding Finding, compare func(a, b string) (int, error)) bool {
	match := debianKernelPackage.FindStringSubmatch(finding.Package)
	if match == nil {
		return false
	}
	prefix := strings.TrimSuffix(finding.Package[:strings.Index(finding.Package, match[1])], "-")
	suffix := finding.Package[strings.Index(finding.Package, match[1])+len(match[1]):]
	for _, item := range packages {
		other := debianKernelPackage.FindStringSubmatch(item.Name)
		if other == nil || other[1] == match[1] || !strings.HasPrefix(item.Name, prefix+"-") || !strings.HasSuffix(item.Name, suffix) {
			continue
		}
		if comparison, err := compare(item.Version, finding.FixedVersion); err == nil && comparison >= 0 {
			return true
		}
	}
	return false
}

// runningRPM reports whether the installed kernel package at installedVersion
// is the running one: uname -r prints its version-release and architecture.
func runningRPM(candidates []inventory.Package, installedVersion, kernel string) bool {
	for _, item := range candidates {
		if item.Version != installedVersion {
			continue
		}
		release := installedVersion
		if _, rest, found := strings.Cut(release, ":"); found {
			release = rest
		}
		if kernel == release || kernel == release+"."+item.Arch || strings.HasPrefix(kernel, release+".") {
			return true
		}
	}
	return false
}
