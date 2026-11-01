package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"deaconguard/internal/checks"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
	"deaconguard/internal/yararules"
)

const promptTimeout = 10 * time.Minute

// PromptSudo is the only question a scan asks: the sudo password, when the
// host allows sudo and it needs one.
const PromptSudo = "sudo"

var (
	errScanInProgress = errors.New("a scan is already running for this host")
	errNoPrompt       = errors.New("this scan is not waiting for input")
)

// scanFunc runs the chosen checks on one host, asking the user through
// options. It is replaced in tests.
type scanFunc func(store.Host, []string, scan.Options) (map[string]any, error)

// Prompt is a question a paused scan is waiting for the user to answer.
type Prompt struct {
	ScanID    string `json:"scan_id"`
	HostID    string `json:"host_id"`
	Address   string `json:"address"`
	Username  string `json:"username"`
	Kind      string `json:"kind"`
	Retry     string `json:"retry,omitempty"`
	CreatedAt string `json:"created_at"`
	reply     chan promptReply
}

type promptReply struct {
	value  []byte
	cancel bool
}

// runner starts scans in the background, one at a time per host, and relays
// the questions they ask. Answers live only in memory for that scan.
type runner struct {
	scan    scanFunc
	ctx     context.Context
	stop    context.CancelFunc
	mu      sync.Mutex
	running map[string]string
	prompts map[string]*Prompt
	logs    map[string]*eventLog
	wg      sync.WaitGroup
	// onFinish, when set, hears about every finished scan, after it is
	// saved: err is why it failed, or nil.
	onFinish func(host store.Host, scanID string, err error)
}

func newRunner(scanner scanFunc) *runner {
	if scanner == nil {
		scanner = scan.Run
	}
	ctx, stop := context.WithCancel(context.Background())
	return &runner{
		scan: scanner, ctx: ctx, stop: stop,
		running: make(map[string]string), prompts: make(map[string]*Prompt), logs: make(map[string]*eventLog),
	}
}

// start begins a scan of host. Unattended scans, such as scheduled ones,
// never wait for a sudo password: nobody is there to type it, so their checks
// run without sudo and say so.
func (r *runner) start(host store.Host, checks []string, unattended bool) (store.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.running[host.ID]; busy {
		return store.Scan{}, errScanInProgress
	}
	if host.Transport == store.TransportAgent {
		return r.queue(host, checks)
	}
	record, err := store.CreateScan(host, checks)
	if err != nil {
		return store.Scan{}, err
	}
	r.running[host.ID] = record.ID
	r.pruneLogs()
	log := newEventLog(host, record, checks)
	r.logs[record.ID] = log
	r.wg.Add(1)
	go r.run(host, record.ID, checks, log, unattended)
	return record, nil
}

// queue records a scan of an agent host for its agent to pick up. r.mu must be held.
func (r *runner) queue(host store.Host, checks []string) (store.Scan, error) {
	if _, busy, err := store.UnfinishedScan(host.ID); err != nil {
		return store.Scan{}, err
	} else if busy {
		return store.Scan{}, errScanInProgress
	}
	record, err := store.QueueScan(host, checks)
	if err != nil {
		return store.Scan{}, err
	}
	r.pruneLogs()
	log := newEventLog(host, record, checks)
	r.logs[record.ID] = log
	log.add(scan.Event{Kind: "phase", Phase: scan.PhaseConnect, Message: fmt.Sprintf("Waiting for the agent on %s to pick up the scan", host.Address)})
	return record, nil
}

// attach returns the live log of an agent scan being picked up, creating one
// for scans queued by the CLI or before a restart.
func (r *runner) attach(host store.Host, record store.Scan) *eventLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	if log, ok := r.logs[record.ID]; ok {
		return log
	}
	r.pruneLogs()
	log := newEventLog(host, record, record.Checks)
	r.logs[record.ID] = log
	log.add(scan.Event{Kind: "phase", Phase: scan.PhaseConnect, Message: fmt.Sprintf("Scan queued for the agent on %s", host.Address)})
	return log
}

// publishFailure closes the live log of a scan that failed without running.
func (r *runner) publishFailure(scanID string, log *eventLog, message string) {
	done := scan.Event{Kind: "done", Status: store.ScanFailed, Message: "Scan failed: " + message}
	log.add(done)
	if encoded, err := json.Marshal(log.snapshot()); err == nil {
		_ = store.SaveScanEvents(scanID, encoded)
	}
	log.finish(store.ScanFailed)
}

func (r *runner) run(host store.Host, scanID string, checks []string, log *eventLog, unattended bool) {
	started := time.Now()
	defer r.wg.Done()
	defer func() {
		r.mu.Lock()
		delete(r.running, host.ID)
		r.mu.Unlock()
	}()
	options := scan.Options{
		SudoPassword: func(retry error) ([]byte, error) {
			return r.ask(host, scanID, Prompt{Kind: PromptSudo, Retry: errorText(retry)})
		},
		Progress:  log.add,
		YARARules: yararules.Provider(),
	}
	if unattended {
		options.SudoPassword = nil
	}
	report, err := r.scan(host, checks, options)
	r.finish(host, scanID, log, report, err, started)
}

// finish stores a scan's outcome, its log, and the pruned history, then
// publishes "done".
func (r *runner) finish(host store.Host, scanID string, log *eventLog, report map[string]any, err error, started time.Time) {
	if err == nil {
		err = compareChanges(host, scanID, report)
	}
	if err == nil {
		sharedKeys(host, scanID, report)
	}
	if err == nil {
		err = store.CompleteScan(scanID, report)
	}
	elapsed := time.Since(started).Round(time.Second)
	done := scan.Event{Kind: "done", Status: store.ScanSucceeded, Message: fmt.Sprintf("Scan finished in %s", elapsed)}
	logScanProblems(host, log.snapshot())
	if err != nil {
		_ = store.FailScan(scanID, err.Error())
		done = scan.Event{Kind: "done", Status: store.ScanFailed, Message: fmt.Sprintf("Scan failed after %s: %s", elapsed, err)}
		serverLog(host.ID, store.LogError, "Scan of %s failed after %s: %s", host.Address, elapsed, err)
	} else {
		serverLog(host.ID, store.LogInfo, "Scan of %s finished in %s", host.Address, elapsed)
	}
	// Everything is saved before "done" is published, so a page that refreshes
	// on seeing it already reads the final status, the saved log, and the
	// pruned history.
	events := log.snapshot()
	final := done
	final.Seq, final.Time = len(events)+1, time.Now().UTC()
	if len(events) > 0 {
		final.Seq = events[len(events)-1].Seq + 1
	}
	if encoded, err := json.Marshal(append(events, final)); err == nil {
		_ = store.SaveScanEvents(scanID, encoded)
	}
	_, _ = store.PruneScans(host.ID, store.KeepScansPerHost)
	log.add(done)
	log.finish(done.Status)
	if r.onFinish != nil {
		r.onFinish(host, scanID, err)
	}
}

// compareChanges reports what the host change check found changed since
// the host's previous record.
func compareChanges(host store.Host, scanID string, report map[string]any) error {
	record, err := store.GetScan(scanID)
	if err != nil || !slices.Contains(record.Checks, checks.Changes) {
		return nil
	}
	previous, _ := previousCheckResult(host, record, checks.Changes)
	return scan.EvaluateChanges(report, previous.Snapshot)
}

// sharedKeys records the SSH keys the attack path check found the host's
// accounts trust, and reports those many other hosts trust too. A failure
// leaves the scan as it is: the check's own findings still stand.
func sharedKeys(host store.Host, scanID string, report map[string]any) {
	record, err := store.GetScan(scanID)
	if err != nil || !slices.Contains(record.Checks, checks.Paths) {
		return
	}
	encoded, _ := json.Marshal(report["check_results"])
	var results map[string]checks.Result
	if json.Unmarshal(encoded, &results) != nil {
		return
	}
	result, ok := results[checks.Paths]
	// Without sudo the keys weren't read; the last record stands.
	if !ok || !result.Privileged || result.Status == checks.StatusFailed || result.Status == checks.StatusSkipped {
		return
	}
	keys := make([]store.HostKey, 0, len(result.Keys))
	var fingerprints []string
	seen := map[string]bool{}
	for _, item := range result.Keys {
		account, fingerprint := scan.KeyFingerprint(item)
		if fingerprint == "" {
			continue
		}
		keys = append(keys, store.HostKey{Account: account, Fingerprint: fingerprint, Root: item.Root, Text: item.Text})
		if !seen[fingerprint] {
			seen[fingerprint] = true
			fingerprints = append(fingerprints, fingerprint)
		}
	}
	if err := store.SetHostKeys(host.ID, keys); err != nil {
		serverLog(host.ID, store.LogError, "Could not record the SSH keys of %s: %v", host.Address, err)
		return
	}
	found, err := store.KeyHosts(host.ID, fingerprints)
	if err != nil {
		serverLog(host.ID, store.LogError, "Could not compare the SSH keys of %s with other hosts: %v", host.Address, err)
		return
	}
	others := map[string][]scan.KeyHost{}
	for fingerprint, hosts := range found {
		for _, other := range hosts {
			others[fingerprint] = append(others[fingerprint], scan.KeyHost{Host: other.Host, Account: other.Account, Root: other.Root})
		}
	}
	if err := scan.EvaluateSharedKeys(report, others); err != nil {
		serverLog(host.ID, store.LogError, "Could not compare the SSH keys of %s with other hosts: %v", host.Address, err)
	}
}

// ask pauses the scan until the user answers prompt in the browser.
func (r *runner) ask(host store.Host, scanID string, prompt Prompt) ([]byte, error) {
	if err := store.WaitForInput(scanID, store.ScanNeedsSudo, prompt.Retry); err != nil {
		return nil, err
	}
	prompt.ScanID, prompt.HostID, prompt.Address, prompt.Username = scanID, host.ID, host.Address, host.Username
	prompt.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	prompt.reply = make(chan promptReply, 1)
	r.mu.Lock()
	r.prompts[scanID] = &prompt
	log := r.logs[scanID]
	r.mu.Unlock()
	if log != nil {
		log.add(scan.Event{Kind: "prompt", Message: "Waiting for you: " + promptLabel(prompt)})
	}
	defer func() {
		r.mu.Lock()
		delete(r.prompts, scanID)
		r.mu.Unlock()
	}()

	timer := time.NewTimer(promptTimeout)
	defer timer.Stop()
	select {
	case reply := <-prompt.reply:
		// Declining the sudo password continues the scan without sudo, so the
		// scan is running again either way.
		if err := store.ResumeScan(scanID); err != nil {
			clear(reply.value)
			return nil, err
		}
		if reply.cancel {
			return nil, fmt.Errorf("scan cancelled: %s", cancelReason(prompt.Kind))
		}
		return reply.value, nil
	case <-timer.C:
		return nil, fmt.Errorf("scan stopped: no answer within %s (%s)", promptTimeout, cancelReason(prompt.Kind))
	case <-r.ctx.Done():
		return nil, errors.New("scan stopped because DeaconGuard was shut down while waiting for input")
	}
}

// respond answers a waiting scan's sudo prompt.
func (r *runner) respond(scanID string, value []byte, cancel bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prompt, ok := r.prompts[scanID]
	if !ok {
		return errNoPrompt
	}
	if !cancel && len(value) == 0 {
		return errors.New("enter the sudo password, or continue without sudo")
	}
	delete(r.prompts, scanID)
	prompt.reply <- promptReply{value: value, cancel: cancel}
	return nil
}

// forget drops a deleted scan's live log.
func (r *runner) forget(scanID string) {
	r.mu.Lock()
	delete(r.logs, scanID)
	r.mu.Unlock()
}

func (r *runner) pending() []Prompt {
	r.mu.Lock()
	defer r.mu.Unlock()
	prompts := make([]Prompt, 0, len(r.prompts))
	for _, prompt := range r.prompts {
		prompts = append(prompts, *prompt)
	}
	sort.Slice(prompts, func(i, j int) bool { return prompts[i].CreatedAt < prompts[j].CreatedAt })
	return prompts
}

// close stops waiting for answers and lets running scans finish.
func (r *runner) close() {
	r.stop()
	r.wg.Wait()
}

func (r *runner) wait() { r.wg.Wait() }

func promptLabel(Prompt) string { return "sudo password" }

func cancelReason(string) string { return "the sudo password was not provided" }

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
