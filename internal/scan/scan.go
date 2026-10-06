// Package scan runs the checks a user chose against one host and assembles
// the report. It reaches the host through a target.Target; today that is the
// machine DeaconGuard runs on. The CLI and the web UI share it.
package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"deaconguard/internal/buildinfo"
	"deaconguard/internal/checks"
	"deaconguard/internal/local"
	"deaconguard/internal/platform"
	"deaconguard/internal/scanner"
	"deaconguard/internal/store"
	"deaconguard/internal/target"
)

// maxConcurrentEvaluations bounds the memory-heavy advisory evaluation when
// several hosts are scanned at once.
const maxConcurrentEvaluations = 2

var evaluationSlots = make(chan struct{}, maxConcurrentEvaluations)

// ErrAgentHost is returned when an agent host is scanned in-process; its
// agent runs the scan instead.
var ErrAgentHost = errors.New("this host is scanned by its DeaconGuard agent through the DeaconGuard server")

type Options struct {
	// SudoPassword is asked for when the host allows sudo but it needs a
	// password. Returning an error continues the scan without sudo.
	SudoPassword func(retry error) ([]byte, error)
	// Progress, when set, receives live events as the scan runs.
	Progress func(Event)
	// CollectInventory, when set, receives the installed packages in place of
	// evaluating them here. An agent uses it to leave the evaluation, which
	// needs the advisory feeds, to the server.
	CollectInventory func(target.Inventory)
}

// Run scans host with the given check IDs, reaching it the way its transport
// says. A failure of the package check fails the whole scan so it can never be
// mistaken for a clean result; other checks record their own failures.
func Run(host store.Host, checkIDs []string, options Options) (map[string]any, error) {
	checkIDs, err := checks.Normalize(checkIDs)
	if err != nil {
		return nil, err
	}
	progress := &reporter{emit: options.Progress}
	started := time.Now()
	if host.Transport == store.TransportAgent {
		return nil, ErrAgentHost
	}
	progress.startPhase(PhaseConnect, fmt.Sprintf("Scanning this machine (%s) as %s", host.Address, local.Username()))
	machine, err := local.New()
	if err == nil {
		progress.send(Event{Kind: "success", Message: fmt.Sprintf("Ready in %s", formatDuration(time.Since(started)))})
	}
	if err != nil {
		progress.endPhase(checks.StatusFailed, err.Error())
		return nil, err
	}
	defer machine.Close()
	return runTarget(machine, host, checkIDs, options, progress)
}

// RunTarget scans a target that is already connected, such as a test double.
func RunTarget(machine target.Target, host store.Host, checkIDs []string, options Options) (map[string]any, error) {
	checkIDs, err := checks.Normalize(checkIDs)
	if err != nil {
		return nil, err
	}
	progress := &reporter{emit: options.Progress}
	progress.startPhase(PhaseConnect, "Using "+host.Address)
	return runTarget(machine, host, checkIDs, options, progress)
}

func runTarget(machine target.Target, host store.Host, checkIDs []string, options Options, progress *reporter) (map[string]any, error) {
	machine.Observe(progress)
	osRelease, err := target.OSRelease(machine)
	if err != nil {
		progress.endPhase(checks.StatusFailed, err.Error())
		return nil, err
	}
	detected, err := platform.Detect(osRelease)
	if err != nil {
		progress.endPhase(checks.StatusFailed, err.Error())
		return nil, err
	}
	progress.endPhase(checks.StatusCompleted, "Detected "+scanner.PlatformName(detected))

	now := time.Now().UTC()
	report := map[string]any{
		"host_id": host.ID, "address": host.Address, "os": scanner.PlatformName(detected),
		"scanned_at": now.Format(time.RFC3339), "checks_run": checkIDs,
		"deaconguard_version": buildinfo.Version,
	}
	results := make(map[string]checks.Result)
	executor := checks.NewExecutor(machine, host.AllowSudo, options.SudoPassword)
	defer executor.Close()
	if _, isLocal := machine.(*local.Target); isLocal && os.Geteuid() == 0 {
		executor.AsRoot()
	}
	sudoNoted := false
	for _, id := range checkIDs {
		progress.startPhase(id, checkName(id))
		phaseStarted := time.Now()
		if id == checks.Packages && options.CollectInventory != nil {
			inventory, err := target.CollectInventory(machine)
			if err != nil {
				progress.endPhase(checks.StatusFailed, err.Error())
				return nil, err
			}
			options.CollectInventory(inventory)
			progress.endPhase(checks.StatusCompleted, fmt.Sprintf("Collected the package list (%s) for the server to evaluate · %s",
				formatBytes(len(inventory.DPKGStatus)+len(inventory.RPMQuery)), formatDuration(time.Since(phaseStarted))))
			continue
		}
		if id == checks.Packages {
			if err := addPackageReport(report, machine, progress); err != nil {
				progress.endPhase(checks.StatusFailed, err.Error())
				return nil, err
			}
			continue
		}
		result := checks.Run(id, executor, detected, now)
		results[id] = result
		if note := executor.SudoNote(); note != "" && !sudoNoted {
			sudoNoted = true
			progress.warn("%s", note)
		}
		progress.findings(result)
		message := result.Summary
		if result.Error != "" {
			message = result.Error
		}
		progress.endPhase(result.Status, fmt.Sprintf("%s · %s", message, formatDuration(time.Since(phaseStarted))))
	}
	if len(results) > 0 {
		report["check_results"] = results
	}
	return report, nil
}

func addPackageReport(report map[string]any, machine target.Target, progress *reporter) error {
	started := time.Now()
	inventory, err := target.CollectInventory(machine)
	if err != nil {
		return err
	}
	return evaluatePackages(report, inventory, progress, started)
}

// EvaluateInventory evaluates packages an agent collected and adds the result
// to its report, as a scan run here would have.
func EvaluateInventory(report map[string]any, inventory target.Inventory, emit func(Event)) error {
	progress := &reporter{emit: emit}
	progress.startPhase(checks.Packages, "Evaluating the packages the agent collected")
	if err := evaluatePackages(report, inventory, progress, time.Now()); err != nil {
		progress.endPhase(checks.StatusFailed, err.Error())
		return err
	}
	return nil
}

func evaluatePackages(report map[string]any, inventory target.Inventory, progress *reporter, started time.Time) error {
	progress.info("Running kernel %s", inventory.Kernel)
	if len(evaluationSlots) == cap(evaluationSlots) {
		progress.info("Waiting for another host's advisory evaluation to finish")
	}
	evaluationSlots <- struct{}{}
	progress.info("Loading the distribution's advisory feed and evaluating installed packages")
	packages, err := scanner.Scan(inventory.OSRelease, inventory.DPKGStatus, inventory.RPMQuery, inventory.Kernel, nil, time.Now().UTC())
	<-evaluationSlots
	if err != nil {
		return err
	}
	feed := packages.AdvisoryDatabase
	if feed.Stale {
		progress.warn("Advisory feed is stale (%.0f hours old): %s", feed.AgeHours, feed.RefreshError)
	} else {
		progress.info("Advisory feed %s, %.1f hours old", feed.Source, feed.AgeHours)
	}
	status := checks.StatusCompleted
	if packages.UnsupportedCount > 0 {
		status = checks.StatusPartial
	}
	progress.endPhase(status, fmt.Sprintf("%d installed packages · %d findings · %d rules not evaluated · %s",
		packages.PackageCount, packages.FindingCount, packages.UnsupportedCount, formatDuration(time.Since(started))))
	encoded, err := json.Marshal(packages)
	if err != nil {
		return err
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return fmt.Errorf("encode package report: %w", err)
	}
	for key, value := range fields {
		report[key] = value
	}
	return nil
}

func checkName(id string) string {
	for _, definition := range checks.Definitions() {
		if definition.ID == id {
			return definition.Name
		}
	}
	return id
}
