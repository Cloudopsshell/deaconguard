package server

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
	"deaconguard/internal/yararules"
)

const testRules = "/*\n * YARA-Forge YARA Rule Package\n * Creation Date: 2026-10-04\n */\n\nrule Example { condition: true }\n"

// cacheTestRules stores a fresh YARA Forge package where yararules.Load
// finds it, so no test downloads anything.
func cacheTestRules(t *testing.T) {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, _ := writer.Create("packages/core/yara-rules-core.yar")
	file.Write([]byte(testRules))
	writer.Close()
	envelope, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"source": yararules.Source, "fetched_at": time.Now().UTC()},
		"data":     archive.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(store.DataDir(), "feeds")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "yara-forge-core.json"), envelope, 0o600); err != nil {
		t.Fatal(err)
	}
}

// enrollTestAgent enrolls an agent of version and returns its host ID and bearer.
func enrollTestAgent(t *testing.T, s *Server, cookie *http.Cookie, hostname, version string) (string, string) {
	t.Helper()
	created := do(t, s, call{method: http.MethodPost, path: "/api/enrollment-tokens", body: map[string]string{"server_url": testOrigin}, cookie: cookie})
	token, err := agentapi.ParseToken(decode[enrollmentTokenResponse](t, created).Token)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := do(t, s, call{method: http.MethodPost, path: "/agent/v1/enroll", body: agentapi.EnrollRequest{
		Secret: token.Secret, Hostname: hostname, Username: "root", OS: "Ubuntu 24.04 LTS", Version: version,
	}})
	identity := decode[agentapi.EnrollResponse](t, enrolled)
	return identity.HostID, identity.HostID + "." + identity.Credential
}

func TestAdvancedScanNeedsANewEnoughAgent(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	oldHost, _ := enrollTestAgent(t, s, cookie, "old-01", "0.4.2")
	newHost, _ := enrollTestAgent(t, s, cookie, "new-01", "0.5.0")

	refused := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + oldHost + "/scans", body: map[string]any{"checks": []string{"yara"}}, cookie: cookie})
	if refused.Code != http.StatusConflict || !strings.Contains(refused.Body.String(), "0.5.0 or later") {
		t.Fatalf("advanced scan on a 0.4.2 agent: %d %s", refused.Code, refused.Body.String())
	}
	if basic := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + oldHost + "/scans", body: map[string]any{"checks": []string{"antivirus"}}, cookie: cookie}); basic.Code != http.StatusAccepted {
		t.Fatalf("basic antivirus scan on a 0.4.2 agent: %d %s", basic.Code, basic.Body.String())
	}
	accepted := do(t, s, call{method: http.MethodPost, path: "/api/hosts/" + newHost + "/scans", body: map[string]any{"checks": []string{"yara"}}, cookie: cookie})
	if accepted.Code != http.StatusAccepted || strings.Join(decode[store.Scan](t, accepted).Checks, ",") != "antivirus,yara" {
		t.Fatalf("advanced scan on a 0.5.0 agent: %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestAgentsGetTheRulesFromTheServer(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	cacheTestRules(t)
	_, bearer := enrollTestAgent(t, s, cookie, "web-01", "0.5.0")

	if anonymous := do(t, s, call{method: http.MethodGet, path: "/agent/v1/yara-rules"}); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("rules without a credential: %d", anonymous.Code)
	}
	response := do(t, s, call{method: http.MethodGet, path: "/agent/v1/yara-rules", bearer: bearer})
	if response.Code != http.StatusOK || response.Header().Get(agentapi.HeaderRulesVersion) != "YARA Forge core 2026-10-04" {
		t.Fatalf("rules: %d, version %q, %s", response.Code, response.Header().Get(agentapi.HeaderRulesVersion), response.Body.String())
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := io.ReadAll(reader)
	if err != nil || string(rules) != testRules {
		t.Fatalf("rules = %q, %v", rules, err)
	}
}
