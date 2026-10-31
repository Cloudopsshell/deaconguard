// Package agent is `deaconguard agent`: it enrolls this machine with a DeaconGuard
// server using an enrollment token, then waits for the server to ask for scans,
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	// Cluster is the name of the Kubernetes cluster a cluster agent checks,
	// from inside it; empty for a machine's agent.
	Cluster string `json:"cluster,omitempty"`
	// MovedFrom is the address the agent used before it moved to the
	// server's port for agents, which it goes back to if that port stops
	// answering, such as after setup server --agent-listen off.
	MovedFrom string `json:"moved_from,omitempty"`
}

// ClusterName is $DEACONGUARD_AGENT_CLUSTER: when set, the agent checks the
// Kubernetes cluster it runs in, with its pod's service account, and
// enrolls under this name, instead of checking a machine.
func ClusterName() string { return strings.TrimSpace(os.Getenv("DEACONGUARD_AGENT_CLUSTER")) }

// Name is what the agent enrolls as: its cluster, or this machine.
func (config Config) Name() string {
	if config.Cluster != "" {
		return config.Cluster
	}
	return local.Hostname()
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

// ErrNotEnrolled means the agent has no configuration yet.
var ErrNotEnrolled = errors.New("this machine is not enrolled")

func LoadConfig(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("%w (%s does not exist); run: sudo deaconguard agent enroll TOKEN", ErrNotEnrolled, path)
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
// enrollment is replaced only when replace is set. name, if not empty, is
// what the server shows the host as instead of its hostname.
func Enroll(ctx context.Context, tokenText, path string, replace bool, name string) (Config, error) {
	token, err := agentapi.ParseToken(tokenText)
	if err != nil {
		return Config{}, err
	}
	if _, err := os.Stat(path); err == nil && !replace {
		return Config{}, fmt.Errorf("this machine is already enrolled (%s); add --force to enroll it again", path)
	}
	cluster := ClusterName()
	if cluster == "" {
		if _, err := local.New(); err != nil {
			return Config{}, err
		}
	}
	client, err := newClient(Config{ServerURL: token.ServerURL, Pin: token.Pin, Cluster: cluster})
	if err != nil {
		return Config{}, err
	}
	request := agentapi.EnrollRequest{
		Secret: token.Secret, Hostname: local.Hostname(), Username: local.Username(), OS: osName(), Version: buildinfo.Version, Name: name,
	}
	if cluster != "" {
		request.Hostname, request.Username, request.OS, request.Kind = cluster, "kubernetes", "Kubernetes", store.KindCluster
	}
	var response agentapi.EnrollResponse
	if err := client.call(ctx, http.MethodPost, "enroll", request, &response, 30*time.Second); err != nil {
		return Config{}, fmt.Errorf("enroll with %s: %w%s", token.ServerURL, err, kubernetesHint(err, os.Getenv("KUBERNETES_SERVICE_HOST") != ""))
	}
	config := Config{ServerURL: token.ServerURL, Pin: token.Pin, HostID: response.HostID, Credential: response.Credential, Cluster: cluster}
	if err := saveConfig(path, config); err != nil {
		return Config{}, fmt.Errorf("enrolled, but could not save %s: %w", path, err)
	}
	return config, nil
}

// kubernetesHint explains, for an agent in a Kubernetes pod, the two usual
// reasons it can't enroll: a token that another agent of the chart used
// first, and a server address only machines outside the cluster reach.
func kubernetesHint(err error, inKubernetes bool) string {
	if !inKubernetes {
		return ""
	}
	if errors.Is(err, errRejected) && strings.Contains(err.Error(), "HTTP 401") {
		return ". In Kubernetes, the chart's agents (one per node, and the cluster agent) share the enrollment secret, " +
			"so its token must be reusable: on the server's Agents page choose Enroll a machine > Kubernetes, put the token in the secret, " +
			"and delete this pod to retry"
	}
	if errors.Is(err, errRejected) {
		return ""
	}
	return ". From a pod, a server in the same cluster is reached at https://SERVICE.NAMESPACE.svc:8444, such as " +
		"https://deaconguard.deaconguard.svc:8444, not at the dashboard's public name: create the token with that address " +
		"(Enroll a machine > Kubernetes fills it in)"
}

// ErrRemoved means the server no longer knows this agent.
var ErrRemoved = errors.New("the server does not recognize this agent; it was removed from the server or its enrollment was lost. Enroll it again with a new token")

// moveRetry is how long an agent waits before trying the server's agent port
// again after it could not reach it.
const moveRetry = time.Hour

// Run waits for scans and runs them until ctx is cancelled. path is where
// the config lives, saved again when the agent moves to the server's agent
// port. logf reports what the agent does, for the service's journal.
func Run(ctx context.Context, config Config, path string, logf func(format string, arguments ...any)) error {
	if config.Cluster == "" {
		if _, err := local.New(); err != nil {
			return err
		}
	}
	client, err := newClient(config)
	if err != nil {
		return err
	}
	log := &agentLog{journal: logf}
	log.info("DeaconGuard agent %s for %s, host %s", buildinfo.Version, config.ServerURL, config.HostID)
	machine, _ := local.New()
	watch := newContainerWatch(machine)
	if config.Cluster != "" {
		// A cluster agent's pod has no containers of its own; it counts the
		// cluster's changes instead, which the server may scan for.
		watch = &containerWatch{run: func(string) ([]byte, error) { return nil, errors.New("a cluster agent") }}
		if cluster, err := connectCluster(); err == nil {
			go cluster.Watch(ctx, func(kind, namespace, name string) { watch.giveBack(1) })
			log.info("Watching the cluster for changes")
		} else {
			log.warn("Can't watch the cluster for changes: %v", err)
		}
		go serveAdmission(ctx, log)
	}
	backoff := time.Duration(0)
	connected := false
	var lastMove, failingSince time.Time
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
		watch.poll(time.Now())
		fresh := watch.take()
		client.setNewContainers(fresh)
		var job agentapi.Job
		err := client.call(ctx, http.MethodGet, "job", nil, &job, agentapi.JobWait+30*time.Second)
		client.setNewContainers(0)
		if err != nil || client.takeDeferred() {
			watch.giveBack(fresh)
		}
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, errUnauthorized):
			return ErrRemoved
		case err != nil:
			connected = false
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			// The agent port stopped answering: the address the agent came
			// from may still lead to the server.
			if returnTo(config) != "" && time.Since(failingSince) >= moveBackAfter {
				back, backClient, backErr := moveBack(ctx, config, path)
				if backErr == nil {
					log.info("%s stopped answering; moved back to %s", config.ServerURL, back.ServerURL)
					config, client, backoff, failingSince = back, backClient, 0, time.Time{}
					continue
				}
				log.warn("%s stopped answering, and %s doesn't either: %v", config.ServerURL, returnTo(config), backErr)
				failingSince = time.Now()
			}
			backoff = min(max(2*backoff, 5*time.Second), time.Minute)
			log.warn("Cannot reach the server, retrying in %s: %v", backoff, err)
			continue
		}
		backoff, failingSince = 0, time.Time{}
		if !connected {
			connected = true
			log.info("Connected to %s; waiting for scans", config.ServerURL)
		}
		// The server keeps a port for agents and asked this one to use it.
		if port := client.agentPort(); port != "" && time.Since(lastMove) >= moveRetry {
			lastMove = time.Now()
			if moved, movedClient, err := moveToPort(ctx, config, port, path); err != nil {
				log.warn("The server asks agents to use port %s, but this machine can't use it: %v. Staying on %s; trying again in an hour.", port, err, config.ServerURL)
			} else {
				log.info("Moved to %s, the server's port for agents", moved.ServerURL)
				config, client = moved, movedClient
			}
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
	var report map[string]any
	var scanErr error
	if config.Cluster != "" {
		report, scanErr = scanCluster(ctx, config, job, events.add)
	} else {
		host := store.Host{ID: config.HostID, Address: local.Hostname(), Username: local.Username(), Transport: store.TransportLocal, AllowSudo: job.AllowSudo}
		report, scanErr = scan.Run(host, job.Checks, scan.Options{
			Progress:         events.add,
			CollectInventory: func(collected target.Inventory) { inventory = &collected },
			YARARules:        func() checks.YARAInput { return client.yaraRules(ctx) },
		})
	}
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
	// suggestedPort is the agent port the server last named, if any.
	mu            sync.Mutex
	suggestedPort string
	// newContainers is sent with the next request for work.
	newContainers int
	// deferred is set when the server deferred the scan they asked for.
	deferred bool
}

// takeDeferred reports whether the server deferred the last count of new
// containers or cluster changes, and forgets it.
func (c *client) takeDeferred() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	deferred := c.deferred
	c.deferred = false
	return deferred
}

func (c *client) setNewContainers(count int) {
	c.mu.Lock()
	c.newContainers = count
	c.mu.Unlock()
}

// agentPort returns the port the server asked agents to use, if it did.
func (c *client) agentPort() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.suggestedPort
}

// moveToPort checks that port on the same host reaches the same server, with
// the same pinned key and this agent's credential, then saves and returns
// the config that uses it.
func moveToPort(ctx context.Context, config Config, port, path string) (Config, *client, error) {
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return Config{}, nil, fmt.Errorf("the server named port %q, which is not a port", port)
	}
	parsed, err := url.Parse(config.ServerURL)
	if err != nil {
		return Config{}, nil, err
	}
	parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	moved := config
	moved.ServerURL = parsed.String()
	if moved.MovedFrom == "" {
		moved.MovedFrom = config.ServerURL
	}
	movedClient, err := newClient(moved)
	if err != nil {
		return Config{}, nil, err
	}
	if err := movedClient.call(ctx, http.MethodGet, agentapi.PathHello, nil, nil, 15*time.Second); err != nil {
		return Config{}, nil, err
	}
	if path != "" {
		if err := saveConfig(path, moved); err != nil {
			return Config{}, nil, fmt.Errorf("save the new address: %w", err)
		}
	}
	return moved, movedClient, nil
}

// returnTo is where an agent on the agent port goes back to: the address it
// moved from, or, for agents that moved before they recorded it (1.8 and
// earlier), the same host on the dashboard's default port. The pinned key
// keeps either from reaching another server.
func returnTo(config Config) string {
	if config.MovedFrom != "" {
		return config.MovedFrom
	}
	parsed, err := url.Parse(config.ServerURL)
	if err != nil || parsed.Port() == "" || parsed.Port() == "8443" {
		return ""
	}
	parsed.Host = net.JoinHostPort(parsed.Hostname(), "8443")
	return parsed.String()
}

// moveBackAfter is how long the agent port has to fail before the agent
// tries the address it came from.
const moveBackAfter = 2 * time.Minute

// moveBack returns to the address the agent used before it moved to the
// agent port, if the server answers there with the same key, and saves it.
func moveBack(ctx context.Context, config Config, path string) (Config, *client, error) {
	back := config
	back.ServerURL, back.MovedFrom = returnTo(config), ""
	if back.ServerURL == "" {
		return Config{}, nil, errors.New("no address to go back to")
	}
	backClient, err := newClient(back)
	if err != nil {
		return Config{}, nil, err
	}
	if err := backClient.call(ctx, http.MethodGet, agentapi.PathHello, nil, nil, 15*time.Second); err != nil {
		return Config{}, nil, err
	}
	if path != "" {
		if err := saveConfig(path, back); err != nil {
			return Config{}, nil, fmt.Errorf("save the address: %w", err)
		}
	}
	return back, backClient, nil
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
	c.mu.Lock()
	if c.newContainers > 0 && strings.HasSuffix(request.URL.Path, "/job") {
		request.Header.Set(agentapi.HeaderNewContainers, strconv.Itoa(c.newContainers))
	}
	c.mu.Unlock()
	// A cluster agent is its cluster, not the pod it runs in.
	if cluster := c.config.Cluster; cluster != "" {
		request.Header.Set(agentapi.HeaderHostname, cluster)
		request.Header.Set(agentapi.HeaderUsername, "kubernetes")
		request.Header.Set(agentapi.HeaderOS, "Kubernetes")
	} else {
		request.Header.Set(agentapi.HeaderHostname, local.Hostname())
		request.Header.Set(agentapi.HeaderUsername, local.Username())
		request.Header.Set(agentapi.HeaderOS, osName())
	}
	if c.config.HostID != "" {
		request.Header.Set("Authorization", "Bearer "+c.config.HostID+"."+c.config.Credential)
	}
	reply, err := c.http.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer reply.Body.Close()
	if port := reply.Header.Get(agentapi.HeaderAgentPort); port != "" || reply.StatusCode < 300 {
		c.mu.Lock()
		c.suggestedPort = port
		c.deferred = c.deferred || reply.Header.Get(agentapi.HeaderChangesDeferred) == "1"
		c.mu.Unlock()
	}
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
	contents, err := os.ReadFile(local.HostPath("/etc/os-release"))
	if err != nil && runtime.GOOS == "darwin" {
		// A Mac has no os-release; sw_vers names the release.
		if output, macErr := exec.Command("/usr/bin/sw_vers").Output(); macErr == nil {
			if release, macErr := platform.MacOSRelease(string(output)); macErr == nil {
				contents, err = []byte(release), nil
			}
		}
	}
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
