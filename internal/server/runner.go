package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"opsarmor/internal/remote"
	"opsarmor/internal/scan"
	"opsarmor/internal/store"
)

const promptTimeout = 10 * time.Minute

const (
	PromptHostKey    = "host_key"
	PromptPassphrase = "passphrase"
	PromptPassword   = "password"
	PromptSudo       = "sudo"
)

var (
	errScanInProgress = errors.New("a scan is already running for this host")
	errNoPrompt       = errors.New("this scan is not waiting for input")
)

// scanFunc runs the chosen checks on one host, asking the user through
// options. It is replaced in tests.
type scanFunc func(store.Host, []string, scan.Options) (map[string]any, error)

// Prompt is a question a paused scan is waiting for the user to answer.
type Prompt struct {
	ScanID      string `json:"scan_id"`
	HostID      string `json:"host_id"`
	Address     string `json:"address"`
	Username    string `json:"username"`
	Port        int    `json:"port"`
	Kind        string `json:"kind"`
	KeyPath     string `json:"key_path,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Retry       string `json:"retry,omitempty"`
	CreatedAt   string `json:"created_at"`
	reply       chan promptReply
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

func (r *runner) start(host store.Host, checks []string) (store.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.running[host.ID]; busy {
		return store.Scan{}, errScanInProgress
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
	go r.run(host, record.ID, checks, log)
	return record, nil
}

func (r *runner) run(host store.Host, scanID string, checks []string, log *eventLog) {
	started := time.Now()
	defer r.wg.Done()
	defer func() {
		r.mu.Lock()
		delete(r.running, host.ID)
		r.mu.Unlock()
	}()
	options := scan.Options{
		Remote: remote.Options{
			ConfirmHostKey: func(key *remote.UnknownHostKey) (bool, error) {
				if _, err := r.ask(host, scanID, Prompt{Kind: PromptHostKey, Fingerprint: key.Fingerprint}); err != nil {
					return false, err
				}
				return true, nil
			},
			Passphrase: func(keyPath string, retry error) ([]byte, error) {
				return r.ask(host, scanID, Prompt{Kind: PromptPassphrase, KeyPath: keyPath, Retry: errorText(retry)})
			},
			Password: func(retry error) ([]byte, error) {
				return r.ask(host, scanID, Prompt{Kind: PromptPassword, Retry: errorText(retry)})
			},
		},
		SudoPassword: func(retry error) ([]byte, error) {
			return r.ask(host, scanID, Prompt{Kind: PromptSudo, Retry: errorText(retry)})
		},
		Progress: log.add,
	}
	report, err := r.scan(host, checks, options)
	if err == nil {
		err = store.CompleteScan(scanID, report)
	}
	elapsed := time.Since(started).Round(time.Second)
	done := scan.Event{Kind: "done", Status: store.ScanSucceeded, Message: fmt.Sprintf("Scan finished in %s", elapsed)}
	if err != nil {
		_ = store.FailScan(scanID, err.Error())
		done = scan.Event{Kind: "done", Status: store.ScanFailed, Message: fmt.Sprintf("Scan failed after %s: %s", elapsed, err)}
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
}

// ask pauses the scan until the user answers prompt in the browser.
func (r *runner) ask(host store.Host, scanID string, prompt Prompt) ([]byte, error) {
	statuses := map[string]string{
		PromptHostKey: store.ScanNeedsTrust, PromptPassphrase: store.ScanNeedsPassphrase,
		PromptPassword: store.ScanNeedsPassword, PromptSudo: store.ScanNeedsSudo,
	}
	if err := store.WaitForInput(scanID, statuses[prompt.Kind], prompt.Retry, prompt.Fingerprint); err != nil {
		return nil, err
	}
	prompt.ScanID, prompt.HostID, prompt.Address, prompt.Username, prompt.Port = scanID, host.ID, host.Address, host.Username, host.Port
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
		return nil, errors.New("scan stopped because OpsArmor was shut down while waiting for input")
	}
}

// respond answers a waiting scan. A host key is only trusted when the
// fingerprint the user confirmed matches the one the host presented.
func (r *runner) respond(scanID string, value []byte, cancel bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prompt, ok := r.prompts[scanID]
	if !ok {
		return errNoPrompt
	}
	if !cancel {
		switch {
		case prompt.Kind == PromptHostKey && string(value) != prompt.Fingerprint:
			return errors.New("the confirmed fingerprint does not match the key presented by the host")
		case prompt.Kind != PromptHostKey && len(value) == 0:
			return fmt.Errorf("enter the %s, or cancel the scan", prompt.Kind)
		}
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

func promptLabel(prompt Prompt) string {
	switch prompt.Kind {
	case PromptHostKey:
		return "verify the SSH host key " + prompt.Fingerprint
	case PromptPassphrase:
		return "passphrase for " + prompt.KeyPath
	case PromptSudo:
		return "sudo password"
	default:
		return "SSH password"
	}
}

func cancelReason(kind string) string {
	switch kind {
	case PromptHostKey:
		return "the SSH host key was not trusted"
	case PromptPassphrase:
		return "the SSH key passphrase was not provided"
	case PromptSudo:
		return "the sudo password was not provided"
	default:
		return "the SSH password was not provided"
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
