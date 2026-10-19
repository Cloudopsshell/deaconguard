package checks

import (
	"deaconguard/internal/containers"
	"deaconguard/internal/lifecycle"
)

// Containers is the running-container check. The agent reads each
// container's packages and libraries (internal/containers); the server
// checks them, as it checks a machine's.
const Containers = "containers"

// ContainerResult is one container: what the agent read (Inventory, which
// the server drops once it has checked it) and what the check found.
type ContainerResult struct {
	containers.Container
	Inventory *containers.Inventory `json:"inventory,omitempty"`
	// HostKernel is the host's running kernel, which containers share.
	HostKernel string `json:"host_kernel,omitempty"`

	OS        string               `json:"os,omitempty"`
	Lifecycle *lifecycle.Lifecycle `json:"lifecycle,omitempty"`
	Packages  int                  `json:"packages"`
	Libraries int                  `json:"libraries"`
	// Severity counts all of the container's vulnerabilities, packages and
	// libraries together; Exploited those known to be exploited (CISA KEV).
	Severity  map[string]int `json:"severity"`
	Exploited int            `json:"exploited"`
	// Fixable counts the vulnerabilities an update in the image fixes.
	Fixable int `json:"fixable"`
	// FixableSeverity counts them by severity.
	FixableSeverity map[string]int `json:"fixable_severity,omitempty"`
	// Findings are the container's vulnerabilities that have a fix or are
	// known to be exploited, most urgent first, at most 300.
	Findings []Finding `json:"findings,omitempty"`
	Notes    []string  `json:"notes,omitempty"`
	// Error says why the container's packages couldn't be checked, such as
	// an unsupported distribution; its libraries are checked anyway.
	Error string `json:"error,omitempty"`
}
