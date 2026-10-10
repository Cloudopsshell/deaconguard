package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/scan"
	"deaconguard/internal/store"
)

type logsResponse struct {
	Entries []store.LogEntry `json:"entries"`
	More    bool             `json:"more"`
}

func TestAgentLogsReachTheDashboard(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, bearer := enrollTestAgent(t, s, cookie, "web-01", "0.6.0")

	lines := agentapi.Logs{Lines: []agentapi.LogLine{
		{At: time.Now().Add(-time.Minute), Level: "info", Message: "Connected to the server; waiting for scans"},
		{At: time.Now(), Level: "warning", Message: "Cannot reach the server, retrying in 5s"},
	}}
	if anonymous := do(t, s, call{method: http.MethodPost, path: "/agent/v1/logs", body: lines}); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("logs without a credential: %d", anonymous.Code)
	}
	if sent := do(t, s, call{method: http.MethodPost, path: "/agent/v1/logs", body: lines, bearer: bearer}); sent.Code != http.StatusNoContent {
		t.Fatalf("send logs: %d %s", sent.Code, sent.Body.String())
	}
	tooMany := agentapi.Logs{Lines: make([]agentapi.LogLine, agentapi.MaxLogLines+1)}
	if refused := do(t, s, call{method: http.MethodPost, path: "/agent/v1/logs", body: tooMany, bearer: bearer}); refused.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too many lines: %d", refused.Code)
	}

	if anonymous := do(t, s, call{method: http.MethodGet, path: "/api/logs"}); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("logs without signing in: %d", anonymous.Code)
	}
	agent := decode[logsResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/logs?source=agent&host=" + hostID, cookie: cookie}))
	if len(agent.Entries) != 2 || agent.Entries[0].Level != "warning" || agent.Entries[0].Host != "web-01" {
		t.Fatalf("agent entries = %+v", agent.Entries)
	}
	// The server logged the enrollment.
	server := decode[logsResponse](t, do(t, s, call{method: http.MethodGet, path: "/api/logs?source=server&q=enrolled", cookie: cookie}))
	if len(server.Entries) != 1 || !strings.Contains(server.Entries[0].Message, "Agent enrolled: web-01") {
		t.Fatalf("server entries = %+v", server.Entries)
	}
	if bad := do(t, s, call{method: http.MethodGet, path: "/api/logs?level=debug", cookie: cookie}); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown level: %d", bad.Code)
	}

	download := do(t, s, call{method: http.MethodGet, path: "/api/logs/download?host=" + hostID, cookie: cookie})
	text := download.Body.String()
	if download.Code != http.StatusOK || !strings.Contains(download.Header().Get("Content-Disposition"), "attachment") ||
		strings.Index(text, "Connected to the server") > strings.Index(text, "Cannot reach") || !strings.Contains(text, "WARNING  agent web-01") {
		t.Fatalf("download: %d %q", download.Code, text)
	}

	// Viewing is audited once, however often the page refreshes; downloads every time.
	views, downloads := 0, 0
	entries, err := store.AuditLog(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		switch entry.Action {
		case "logs.view":
			views++
		case "logs.download":
			downloads++
		}
	}
	if views != 1 || downloads != 1 {
		t.Fatalf("audited %d views and %d downloads", views, downloads)
	}
}

func TestOnlyScanProblemsAreLogged(t *testing.T) {
	newNetworkTestServer(t)
	host := store.Host{ID: "h1", Address: "web-01"}
	logScanProblems(host, []scan.Event{
		{Kind: "info", Phase: "packages", Message: "Advisory feed loaded"},
		{Kind: "warning", Phase: "packages", Message: "Advisory feed is stale (30 hours old)"},
		{Kind: "warning", Phase: "packages", Message: "Advisory feed is stale (30 hours old)"},
		{Kind: "warning", Phase: "config", Status: "partial", Message: "2 issues found · 7 ms"},
		{Kind: "warning", Phase: "antivirus", Status: "skipped", Message: "ClamAV is not installed on this host"},
		{Kind: "error", Phase: "integrity", Status: "failed", Message: "dpkg --verify failed"},
	})
	entries, _, err := store.Logs(store.LogQuery{HostID: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	var messages []string
	for i := len(entries) - 1; i >= 0; i-- {
		messages = append(messages, entries[i].Level+": "+entries[i].Message)
	}
	want := []string{
		"warning: Scan of web-01: Advisory feed is stale (30 hours old)",
		"warning: Scan of web-01: the antivirus check skipped: ClamAV is not installed on this host",
		"error: Scan of web-01: the integrity check failed: dpkg --verify failed",
	}
	if strings.Join(messages, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logged:\n%s", strings.Join(messages, "\n"))
	}
}
