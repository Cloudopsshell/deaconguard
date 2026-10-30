package server

import (
	"net/http"
	"strings"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

func TestHostsCanBeRenamed(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, bearer := enrollTestAgent(t, s, cookie, "ip-10-92-0-178", "1.17.0")
	before := completePackages(t, mustHost(t, hostID), kevFinding("CVE-2024-38475"))

	rename := func(name string) *http.Response {
		t.Helper()
		return do(t, s, call{method: http.MethodPatch, path: "/api/hosts/" + hostID, cookie: cookie, body: map[string]any{"name": name}}).Result()
	}
	if response := rename("  payments-api-prod  "); response.StatusCode != http.StatusOK {
		t.Fatalf("rename: %d", response.StatusCode)
	}
	host := mustHost(t, hostID)
	if host.Address != "payments-api-prod" || host.Name != "payments-api-prod" || host.Hostname != "ip-10-92-0-178" {
		t.Fatalf("renamed: %+v", host)
	}
	// Its past scans, the vulnerabilities list and the log use the name.
	if record, _ := store.GetScan(before); record.Address != "payments-api-prod" {
		t.Fatalf("past scan: %q", record.Address)
	}
	if findings, _ := store.LatestFindings(); len(findings) != 1 || findings[0].Address != "payments-api-prod" {
		t.Fatalf("findings: %+v", findings)
	}
	for _, search := range []string{"payments", "ip-10-92"} {
		if entries, _, _ := store.Logs(store.LogQuery{Search: search, Limit: 50}); len(entries) == 0 {
			t.Fatalf("the log has nothing for %q", search)
		}
	}

	// Checking in with its hostname keeps the name, and records a new hostname.
	do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + hostID + "/scans", cookie: cookie, body: map[string]any{"checks": []string{"packages"}}})
	do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer,
		headers: map[string]string{agentapi.HeaderVersion: "1.17.0", agentapi.HeaderHostname: "ip-10-92-0-200"}})
	if host := mustHost(t, hostID); host.Address != "payments-api-prod" || host.Hostname != "ip-10-92-0-200" {
		t.Fatalf("after a check-in: %+v", host)
	}

	if response := rename(strings.Repeat("x", store.MaxHostName+1)); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("too long: %d", response.StatusCode)
	}
	if response := rename("two\nlines"); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("a line break: %d", response.StatusCode)
	}
	// Empty goes back to the hostname.
	rename("")
	if host := mustHost(t, hostID); host.Address != "ip-10-92-0-200" || host.Name != "" {
		t.Fatalf("reset: %+v", host)
	}
	entries, _ := store.AuditLog(20)
	renamed := 0
	for _, entry := range entries {
		if entry.Action == "host.rename" {
			renamed++
		}
	}
	if renamed != 2 {
		t.Fatalf("audit log: %d renames", renamed)
	}
}

func TestAgentsEnrollWithAName(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	created := do(t, s, call{method: http.MethodPost, path: "/api/enrollment-tokens", body: map[string]string{"server_url": testOrigin}, cookie: cookie})
	token, err := agentapi.ParseToken(decode[enrollmentTokenResponse](t, created).Token)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: agentapi.EnrollRequest{
		Secret: token.Secret, Hostname: "ip-10-0-0-5", Username: "root", OS: "Ubuntu 24.04 LTS", Version: "1.18.0", Name: "billing-db",
	}})
	identity := decode[agentapi.EnrollResponse](t, enrolled)
	if host := mustHost(t, identity.HostID); host.Address != "billing-db" || host.Hostname != "ip-10-0-0-5" {
		t.Fatalf("enrolled: %+v", host)
	}
}

func mustHost(t *testing.T, id string) store.Host {
	t.Helper()
	host, err := store.GetHost(id)
	if err != nil {
		t.Fatal(err)
	}
	return host
}
