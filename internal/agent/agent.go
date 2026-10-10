// Package agent is `deaconguard agent`: it enrolls this machine with a DeaconGuard
// server using a one-time token, then waits for the server to ask for scans,
// runs them here, and sends back the results. It only makes outbound HTTPS
// requests to the server; it opens no port.
package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/buildinfo"
	"deaconguard/internal/checks"
	"deaconguard/internal/local"
	"deaconguard/internal/platform"
	"deaconguard/internal/scan"
	"deaconguard/internal/scanner"
	"deaconguard/internal/store"
	"deaconguard/internal/target"
	"deaconguard/internal/yararules"
)

// Config is what enrollment gives the agent. It holds a credential, so it is
// readable by its owner only.
type Config struct {
	ServerURL  string `json:"server_url"`
	Pin        string `json:"pin"`
	HostID     string `json:"host_id"`
	Credential string `json:"credential"`
}

// SystemConfigPath is where the agent service keeps its configuration.
const SystemConfigPath = "/etc/deaconguard/agent.json"

// ConfigPath is $DEACONGUARD_AGENT_CONFIG, SystemConfigPath for root, or a file
// in the user's configuration directory.
func ConfigPath() string {
	if configured := os.Getenv("DEACONGUARD_AGENT_CONFIG"); configured != "" {
		return configured
	}
	if os.Geteuid() == 0 {
		return SystemConfigPath
	}
	if directory, err := os.UserConfigDir(); err == nil {
		return filepath.Join(directory, "deaconguard", "agent.json")
	}
	return SystemConfigPath
}

func LoadConfig(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("this machine is not enrolled (%s does not exist); run: sudo deaconguard agent enroll TOKEN", path)
	}
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(contents, &config); err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if config.ServerURL == "" || config.Pin == "" || config.HostID == "" || config.Credential == "" {
		return Config{}, fmt.Errorf("%s is incomplete; enroll again", path)
	}
	return config, nil
}

func saveConfig(path string, config Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Enroll spends token and saves the agent's configuration at path. An existing
// enrollment is replaced only when replace is set.
func Enroll(ctx context.Context, tokenText, path string, replace bool) (Config, error) {
	token, err := agentapi.ParseToken(tokenText)
	if err != nil {
		return Config{}, err
	}
	if _, err := os.Stat(path); err == nil && !replace {
		return Config{}, fmt.Errorf("this machine is already enrolled (%s); add --force to enroll it again", path)
	}
	if _, err := local.New(); err != nil {
		return Config{}, err
	}
	client, err := newClient(Config{ServerURL: token.ServerURL, Pin: token.Pin})
	if err != nil {
		return Config{}, err
	}
	request := agentapi.EnrollRequest{
		Secret: token.Secret, Hostname: local.Hostname(), Username: local.Username(), OS: osName(), Version: buildinfo.Version,
	}
	var response agentapi.EnrollResponse
	if err := client.call(ctx, http.MethodPost, "enroll", request, &response, 30*time.Second); err != nil {
		return Config{}, fmt.Errorf("enroll with %s: %w", token.ServerURL, err)
	}
	config := Config{ServerURL: token.ServerURL, Pin: token.Pin, HostID: response.HostID, Credential: response.Credential}
	if err := saveConfig(path, config); err != nil {
		return Config{}, fmt.Errorf("enrolled, but could not save %s: %w", path, err)
	}
	return config, nil
}

// ErrRemoved means the server no longer knows this agent.
var ErrRemoved = errors.New("the server does not recognize this agent; it was removed from the server or its enrollment was lost. Enroll it again with a new token")

// Run waits for scans and runs them until ctx is cancelled. logf reports
// what the agent does, for the service's journal.
func Run(ctx context.Context, config Config, logf func(format string, arguments ...any)) error {
	if _, err := local.New(); err != nil {
		return err
	}
	client, err := newClient(config)
	if err != nil {
		return err
	}
	log := &agentLog{journal: logf}
	log.info("DeaconGuard agent %s for %s, host %s", buildinfo.Version, config.ServerURL, config.HostID)
	backoff := time.Duration(0)
	connected := false
	for ctx.Err() == nil {
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
		}
		// Before waiting for work, so lines kept while the server could not be
		// reached arrive as soon as it answers again.
		log.send(ctx, client)
		var job agentapi.Job
		err := client.call(ctx, http.MethodGet, "job", nil, &job, agentapi.JobWait+30*time.Second)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, errUnauthorized):
			return ErrRemoved
		case err != nil:
			connected = false
			backoff = min(max(2*backoff, 5*time.Second), time.Minute)
			log.warn("Cannot reach the server, retrying in %s: %v", backoff, err)
			continue
		}
		backoff = 0
		if !connected {
			connected = true
			log.info("Connected to %s; waiting for scans", config.ServerURL)
		}
		log.send(ctx, client)
		if job.ScanID == "" {
			continue
		}
		log.info("Scan %s: running %s", job.ScanID, strings.Join(job.Checks, ", "))
		if err := runJob(ctx, client, config, job); err != nil {
			log.fail("Scan %s: %v", job.ScanID, err)
		} else {
			log.info("Scan %s: sent the results", job.ScanID)
		}
		log.send(ctx, client)
	}
	return nil
}

func runJob(ctx context.Context, client *client, config Config, job agentapi.Job) error {
	events := &eventBuffer{}
	flushDone := make(chan struct{})
	flushCtx, stopFlushing := context.WithCancel(ctx)
	go func() {
		defer close(flushDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-flushCtx.Done():
				return
			case <-ticker.C:
				events.flush(flushCtx, client, job.ScanID)
			}
		}
	}()
	var inventory *target.Inventory
	host := store.Host{ID: config.HostID, Address: local.Hostname(), Username: local.Username(), Transport: store.TransportLocal, AllowSudo: job.AllowSudo}
	report, scanErr := scan.Run(host, job.Checks, scan.Options{
		Progress:         events.add,
		CollectInventory: func(collected target.Inventory) { inventory = &collected },
		YARARules:        func() checks.YARAInput { return client.yaraRules(ctx) },
	})
	stopFlushing()
	<-flushDone
	events.flush(ctx, client, job.ScanID)
	result := agentapi.Result{Report: report, Inventory: inventory}
	if scanErr != nil {
		result = agentapi.Result{Error: scanErr.Error()}
	}
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = client.call(ctx, http.MethodPost, "scans/"+url.PathEscape(job.ScanID)+"/result", result, nil, 5*time.Minute); err == nil ||
			errors.Is(err, errRejected) || ctx.Err() != nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("send the results: %w", err)
	}
	return scanErr
}

// eventBuffer batches live progress lines for the server.
type eventBuffer struct {
	mu     sync.Mutex
	events []scan.Event
}

func (b *eventBuffer) add(event scan.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) < 5000 {
		b.events = append(b.events, event)
	}
}

func (b *eventBuffer) flush(ctx context.Context, client *client, scanID string) {
	b.mu.Lock()
	pending := b.events
	b.events = nil
	b.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	// Progress is best effort: a lost batch only thins the live log.
	_ = client.call(ctx, http.MethodPost, "scans/"+url.PathEscape(scanID)+"/events", agentapi.Events{Events: pending}, nil, 30*time.Second)
}

var (
	errUnauthorized = errors.New("unauthorized")
	errRejected     = errors.New("the server rejected the request")
)

type client struct {
	base   string
	config Config
	http   *http.Client
}

func newClient(config Config) (*client, error) {
	if err := agentapi.ValidateServerURL(config.ServerURL); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(config.ServerURL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = agentapi.ClientTLS(parsed.Hostname(), config.Pin)
	// The agent talks to its server directly; a proxy would see the pinned
	// connection fail anyway.
	transport.Proxy = nil
	return &client{
		base:   strings.TrimSuffix(config.ServerURL, "/") + agentapi.PathPrefix,
		config: config,
		http:   &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (c *client) call(ctx context.Context, method, path string, body, response any, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	contents, _, err := c.exchange(ctx, method, path, body, 1<<20)
	if err != nil || response == nil || len(contents) == 0 {
		return err
	}
	return json.Unmarshal(contents, response)
}

// exchange sends one request and returns the body of a successful reply,
// reading at most limit bytes of it.
func (c *client) exchange(ctx context.Context, method, path string, body any, limit int64) ([]byte, http.Header, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	request.Header.Set(agentapi.HeaderVersion, buildinfo.Version)
	request.Header.Set(agentapi.HeaderHostname, local.Hostname())
	request.Header.Set(agentapi.HeaderUsername, local.Username())
	request.Header.Set(agentapi.HeaderOS, osName())
	if c.config.HostID != "" {
		request.Header.Set("Authorization", "Bearer "+c.config.HostID+"."+c.config.Credential)
	}
	reply, err := c.http.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer reply.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(reply.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	switch {
	case reply.StatusCode == http.StatusNoContent || reply.StatusCode == http.StatusAccepted:
		return nil, reply.Header, nil
	case reply.StatusCode >= 200 && reply.StatusCode < 300:
		if int64(len(contents)) > limit {
			return nil, nil, fmt.Errorf("the server's reply is larger than %d bytes", limit)
		}
		return contents, reply.Header, nil
	}
	contents = contents[:min(int64(len(contents)), 1<<20)]
	var failure struct {
		Error string `json:"error"`
	}
	message := strings.TrimSpace(string(contents))
	if json.Unmarshal(contents, &failure) == nil && failure.Error != "" {
		message = failure.Error
	}
	if reply.StatusCode == http.StatusUnauthorized && c.config.HostID != "" {
		return nil, nil, fmt.Errorf("%w: %s", errUnauthorized, message)
	}
	if reply.StatusCode >= 400 && reply.StatusCode < 500 {
		return nil, nil, fmt.Errorf("%w (HTTP %d): %s", errRejected, reply.StatusCode, message)
	}
	return nil, nil, fmt.Errorf("HTTP %d: %s", reply.StatusCode, message)
}

// yaraRules fetches the advanced antivirus scan's rules from the server. A
// failure becomes the reason the report gives for skipping that scan.
func (c *client) yaraRules(ctx context.Context) checks.YARAInput {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	compressed, header, err := c.exchange(ctx, http.MethodGet, agentapi.PathYARARules, nil, agentapi.MaxYARARulesBytes)
	if err != nil {
		return checks.YARAInput{Unavailable: "the server could not provide the YARA rules: " + err.Error()}
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return checks.YARAInput{Unavailable: "the server's YARA rules are not gzip data: " + err.Error()}
	}
	rules, err := io.ReadAll(io.LimitReader(reader, 64<<20))
	if err != nil {
		return checks.YARAInput{Unavailable: "read the server's YARA rules: " + err.Error()}
	}
	input, err := yararules.Parse(rules)
	if err != nil {
		return checks.YARAInput{Unavailable: err.Error()}
	}
	if version := header.Get(agentapi.HeaderRulesVersion); version != "" {
		input.Version = version
	}
	return input
}

func osName() string {
	contents, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	if detected, err := platform.Detect(string(contents)); err == nil {
		return scanner.PlatformName(detected)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if value, found := strings.CutPrefix(line, "PRETTY_NAME="); found {
			return strings.Trim(value, `"'`)
		}
	}
	return ""
}
