package server

import (
	"strings"
	"testing"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

// The first machine that enrolls is scanned once, with the recommended
// checks its agent can run; later ones aren't, nor is a cluster.
func TestFirstScanAfterInstall(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	// newNetworkTestServer takes the first scan: give it back, as on a
	// server just installed.
	if err := store.SetMeta("first_scan", "0"); err != nil {
		t.Fatal(err)
	}

	clusterID, _ := enrollTestCluster(t, s, cookie, "prod-eu")
	if scans, _ := store.ListScans(clusterID, 5); len(scans) != 0 {
		t.Fatalf("a cluster got the first scan: %+v", scans)
	}
	first, bearer := enrollTestAgent(t, s, cookie, "this-server", "1.31.0")
	job := decode[agentapi.Job](t, do(t, s, call{method: "GET", path: "/agent/v1/job", bearer: bearer,
		headers: map[string]string{agentapi.HeaderVersion: "1.31.0"}}))
	if got := strings.Join(job.Checks, ","); got != "packages,malware,config,changes,paths" {
		t.Fatalf("first scan checks: %q (%+v)", got, job)
	}
	second, _ := enrollTestAgent(t, s, cookie, "web-01", "1.31.0")
	if scans, _ := store.ListScans(second, 5); len(scans) != 0 {
		t.Fatalf("the second machine was scanned too: %+v", scans)
	}
	if scans, _ := store.ListScans(first, 5); len(scans) != 1 {
		t.Fatalf("first machine scans: %+v", scans)
	}
}
