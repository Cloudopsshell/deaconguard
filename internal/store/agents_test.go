package store

import (
	"errors"
	"strings"
	"testing"
)

func enrollWith(t *testing.T, secret, hostname, kind string) (Host, string, error) {
	t.Helper()
	return EnrollAgent(secret, AgentEnrollment{Kind: kind, Hostname: hostname, Username: "root", Version: "1.21.0", OS: "Ubuntu 26.04 LTS"})
}

func TestEnrollmentRejectionsSayWhy(t *testing.T) {
	withTempDataDir(t)
	once, onceSecret, err := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := enrollWith(t, onceSecret, "web-1", ""); err != nil {
		t.Fatal(err)
	}
	_, _, err = enrollWith(t, onceSecret, "web-2", "")
	if !errors.Is(err, ErrInvalidEnrollmentToken) || !strings.Contains(err.Error(), once.ID[:8]+" is a one-time token, already used") {
		t.Fatalf("used: %v", err)
	}
	revoked, revokedSecret, err := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeEnrollmentToken(revoked.ID, "admin", false); err != nil {
		t.Fatal(err)
	}
	_, _, err = enrollWith(t, revokedSecret, "web-3", "")
	if !errors.Is(err, ErrInvalidEnrollmentToken) || !strings.Contains(err.Error(), revoked.ID[:8]+" was revoked on ") {
		t.Fatalf("revoked: %v", err)
	}
	_, _, err = enrollWith(t, "not-a-token", "web-4", "")
	if !errors.Is(err, ErrInvalidEnrollmentToken) || !strings.Contains(err.Error(), "isn't known to this server") {
		t.Fatalf("unknown: %v", err)
	}
}

func TestRevokingDisconnectsTheMachinesATokenEnrolled(t *testing.T) {
	withTempDataDir(t)
	token, secret, err := CreateEnrollmentToken("https://deaconguard.deaconguard.svc:8444", "admin", TokenOptions{Reusable: true, Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	node, nodeCredential, err := enrollWith(t, secret, "node-1", "")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err := enrollWith(t, secret, "prod", KindCluster)
	if err != nil {
		t.Fatal(err)
	}
	other, otherSecret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{})
	bystander, bystanderCredential, err := enrollWith(t, otherSecret, "vm-1", "")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := GetEnrollmentToken(token.ID)
	if err != nil || len(listed.Hosts) != 2 || listed.Hosts[0].ID != cluster.ID {
		t.Fatalf("token's hosts: %+v, %v", listed.Hosts, err)
	}

	_, disconnected, err := RevokeEnrollmentToken(token.ID, "admin", true)
	if err != nil || len(disconnected) != 2 {
		t.Fatalf("disconnected %+v, %v", disconnected, err)
	}
	_, err = AuthenticateAgent(node.ID, nodeCredential, "1.21.0", "10.0.0.1", "8444")
	var refused AgentDisconnected
	if !errors.As(err, &refused) || !errors.Is(err, ErrUnknownAgent) ||
		!strings.Contains(err.Error(), "disconnected on ") || !strings.Contains(err.Error(), "by admin: its enrollment token "+token.ID[:8]+" was revoked") {
		t.Fatalf("disconnected agent: %v", err)
	}
	// A wrong credential learns nothing of why.
	if _, err := AuthenticateAgent(node.ID, "wrong", "1.21.0", "10.0.0.1", "8444"); err != ErrUnknownAgent {
		t.Fatalf("wrong credential: %v", err)
	}
	if _, err := AuthenticateAgent(bystander.ID, bystanderCredential, "1.21.0", "10.0.0.2", "8444"); err != nil {
		t.Fatalf("another token's machine: %v", err)
	}
	stored, err := GetHost(node.ID)
	if err != nil || stored.Disconnected == nil || stored.Disconnected.By != "admin" {
		t.Fatalf("host: %+v, %v", stored, err)
	}
	_ = other

	// Enrolled again with a new token, the machine gets its host back.
	_, fresh, _ := CreateEnrollmentToken("https://deaconguard.deaconguard.svc:8444", "admin", TokenOptions{Reusable: true})
	again, credential, err := enrollWith(t, fresh, "node-1", "")
	if err != nil || again.ID != node.ID || again.Disconnected != nil {
		t.Fatalf("reconnected: %+v, %v", again, err)
	}
	if _, err := AuthenticateAgent(node.ID, credential, "1.21.0", "10.0.0.1", "8444"); err != nil {
		t.Fatalf("reconnected agent: %v", err)
	}
	if _, err := AuthenticateAgent(node.ID, nodeCredential, "1.21.0", "10.0.0.1", "8444"); err == nil {
		t.Fatal("the old credential still works")
	}
}

func TestRevokingWithoutDisconnectingKeepsMachines(t *testing.T) {
	withTempDataDir(t)
	token, secret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	host, credential, err := enrollWith(t, secret, "node-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, disconnected, err := RevokeEnrollmentToken(token.ID, "admin", false); err != nil || len(disconnected) != 0 {
		t.Fatalf("%+v, %v", disconnected, err)
	}
	if _, err := AuthenticateAgent(host.ID, credential, "1.21.0", "10.0.0.1", "8444"); err != nil {
		t.Fatalf("kept machine: %v", err)
	}
}

func TestDeleteRevokedTokens(t *testing.T) {
	withTempDataDir(t)
	active, _, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{})
	first, _, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{})
	second, _, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	for _, id := range []string{first.ID, second.ID} {
		if _, _, err := RevokeEnrollmentToken(id, "admin", false); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := DeleteRevokedTokens()
	if err != nil || removed != 2 {
		t.Fatalf("removed %d, %v", removed, err)
	}
	tokens, err := ListEnrollmentTokens()
	if err != nil || len(tokens) != 1 || tokens[0].ID != active.ID {
		t.Fatalf("left: %+v, %v", tokens, err)
	}
}

func TestSchemaV29LinksEarlierAgentsToTheirToken(t *testing.T) {
	withTempDataDir(t)
	db, err := database()
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`INSERT INTO hosts (id, address, username, transport, allow_sudo, kind, created_at) VALUES
			('h1', 'node-1', 'root', 'agent', 1, 'machine', '2026-10-31T18:00:00Z'),
			('h2', 'prod', '', 'agent', 1, 'cluster', '2026-10-31T18:00:00Z'),
			('h3', 'vm-1', 'root', 'agent', 1, 'machine', '2026-10-31T18:00:00Z'),
			('h4', 'vm-2', 'root', 'agent', 1, 'machine', '2026-10-31T18:00:00Z')`,
		`INSERT INTO agents (host_id, credential_hash, enrolled_at, last_seen_at) VALUES
			('h1', 'x1', '2026-10-31T18:30:00Z', '2026-10-31T18:30:00Z'),
			('h2', 'x2', '2026-10-31T18:31:00Z', '2026-10-31T18:31:00Z'),
			('h3', 'x3', '2026-10-31T12:00:00Z', '2026-10-31T12:00:00Z'),
			('h4', 'x4', '2026-10-31T10:00:00Z', '2026-10-31T10:00:00Z')`,
		// t1, reusable, the only one that could enroll at 18:30; t2 the
		// one-time token for h3; t3 and t4 both reusable at 10:00.
		`INSERT INTO enrollment_tokens (id, secret_hash, server_url, created_by, created_at, expires_at, used_at, host_id, revoked_at, reusable, uses) VALUES
			('t1', 's1', 'u', 'admin', '2026-10-31T18:20:00Z', '2026-11-30T18:20:00Z', '2026-10-31T18:31:00Z', NULL, NULL, 1, 2),
			('t2', 's2', 'u', 'admin', '2026-10-31T11:00:00Z', '2026-11-01T11:00:00Z', '2026-10-31T12:00:00Z', 'h3', NULL, 0, 1),
			('t3', 's3', 'u', 'admin', '2026-10-31T09:00:00Z', '2026-10-31T17:00:00Z', '2026-10-31T10:00:00Z', NULL, NULL, 1, 1),
			('t4', 's4', 'u', 'admin', '2026-10-31T09:30:00Z', '2026-10-31T17:00:00Z', '2026-10-31T10:00:00Z', NULL, NULL, 1, 1)`,
		`UPDATE agents SET token_id = ''`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	// The migration's backfill, run again on these rows.
	_, backfill, _ := strings.Cut(schemaV29, "ALTER TABLE hosts ADD COLUMN cluster_id TEXT NOT NULL DEFAULT '';")
	backfill, _, _ = strings.Cut(backfill, "PRAGMA")
	if _, err := db.Exec(backfill); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"h1": "t1", "h2": "t1", "h3": "t2", "h4": ""}
	for host, token := range want {
		var got string
		if err := db.QueryRow("SELECT token_id FROM agents WHERE host_id = ?", host).Scan(&got); err != nil || got != token {
			t.Errorf("%s: token %q, want %q (%v)", host, got, token, err)
		}
	}
}

func TestLinkClusterNodes(t *testing.T) {
	withTempDataDir(t)
	_, secret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	cluster, _, _ := enrollWith(t, secret, "prod", KindCluster)
	node, _, _ := enrollWith(t, secret, "node-1", "")
	elsewhere, _, _ := enrollWith(t, secret, "vm-1", "")
	// Another machine called node-1, enrolled with another token.
	_, otherSecret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{})
	twin, _, _ := enrollWith(t, otherSecret, "node-1", "")
	if err := LinkClusterNodes(cluster.ID, []string{"node-1", "node-2"}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{node.ID: cluster.ID, twin.ID: "", elsewhere.ID: ""} {
		if host, _ := GetHost(id); host.ClusterID != want {
			t.Errorf("%s: cluster %q, want %q", host.Address, host.ClusterID, want)
		}
	}
	// A node gone from the cluster is unlinked.
	if err := LinkClusterNodes(cluster.ID, []string{"node-2"}); err != nil {
		t.Fatal(err)
	}
	if host, _ := GetHost(node.ID); host.ClusterID != "" {
		t.Errorf("still linked: %+v", host)
	}
}
