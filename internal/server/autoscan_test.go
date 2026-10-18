package server

import (
	"net/http"
	"testing"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/store"
)

func TestNewContainersAreScannedWhenTurnedOn(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, bearer := enrollTestAgent(t, s, cookie, "docker-01", "1.2.0")
	host, _ := store.GetHost(hostID)
	if host.AutoScanContainers {
		t.Fatal("automatic container scans must be off by default")
	}

	// Off: new containers queue nothing.
	s.agents.scanNewContainers(host, "1.2.0", 3)
	if taken, _ := store.TakeAutoScan(hostID, time.Now(), time.Minute); taken {
		t.Fatal("a host with the setting off must not be claimed")
	}

	turnedOn := do(t, s, call{method: http.MethodPatch, path: "/api/hosts/" + hostID, body: map[string]bool{"auto_scan_containers": true}, cookie: cookie})
	if turnedOn.Code != http.StatusOK || !decode[store.Host](t, turnedOn).AutoScanContainers {
		t.Fatalf("turn on: %d %s", turnedOn.Code, turnedOn.Body.String())
	}

	// An agent that saw new containers gets a container scan right away.
	job := do(t, s, call{method: http.MethodGet, path: "/agent/v1/job", bearer: bearer,
		headers: map[string]string{agentapi.HeaderNewContainers: "2", agentapi.HeaderVersion: "1.2.0"}})
	got := decode[agentapi.Job](t, job)
	if job.Code != http.StatusOK || got.ScanID == "" || len(got.Checks) != 1 || got.Checks[0] != "containers" {
		t.Fatalf("job = %d %+v", job.Code, got)
	}

	// Within the interval, more new containers don't queue another scan.
	host, _ = store.GetHost(hostID)
	if taken, _ := store.TakeAutoScan(hostID, time.Now(), autoScanInterval); taken {
		t.Error("a second automatic scan within the interval must not be claimed")
	}
	if taken, _ := store.TakeAutoScan(hostID, time.Now().Add(autoScanInterval+time.Second), autoScanInterval); !taken {
		t.Error("after the interval, the next automatic scan must be claimed")
	}
}

func TestOldAgentsAreNotAutoScanned(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, _ := enrollTestAgent(t, s, cookie, "old-01", "1.1.0")
	host, _ := store.SetAutoScanContainers(hostID, true)
	s.agents.scanNewContainers(host, "1.1.0", 5)
	if taken, _ := store.TakeAutoScan(hostID, time.Now(), time.Minute); !taken {
		t.Error("an agent without the container check must not use up the automatic scan")
	}
}
