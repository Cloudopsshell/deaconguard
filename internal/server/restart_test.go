package server

import (
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"deaconguard/internal/runstate"
	"deaconguard/internal/store"
)

func TestARestartExplainsTheScansItCutShort(t *testing.T) {
	s := newNetworkTestServer(t)
	cookie := signIn(t, s)
	hostID, _ := enrollTestAgent(t, s, cookie, "web-01", "0.5.1")
	host, err := store.GetHost(hostID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.QueueScan(host, []string{"packages"}); err != nil {
		t.Fatal(err)
	}
	running, found, err := store.ClaimQueuedScan(hostID)
	if err != nil || !found {
		t.Fatalf("ClaimQueuedScan() = %v, %v", found, err)
	}

	// The next run of the server finds out the machine ran out of memory.
	stop := &runstate.Stop{Kind: runstate.KindOutOfMemory, Message: "The machine ran out of memory and the kernel stopped the DeaconGuard server.", DetectedAt: time.Now().UTC()}
	if err := store.SetLastStop(stop); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNetwork(fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}, nil, testPin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)

	scan, err := store.GetScan(running.ID)
	want := "The DeaconGuard server stopped while this scan was running. The machine ran out of memory and the kernel stopped the DeaconGuard server. Run the scan again."
	if err != nil || scan.Status != store.ScanFailed || scan.Error != want {
		t.Fatalf("scan = %q %q, %v", scan.Status, scan.Error, err)
	}
	if anonymous := do(t, restarted, call{method: http.MethodGet, path: "/api/server-status"}); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("status without signing in: %d", anonymous.Code)
	}
	status := decode[struct {
		LastStop *runstate.Stop `json:"last_stop"`
	}](t, do(t, restarted, call{method: http.MethodGet, path: "/api/server-status", cookie: cookie}))
	if status.LastStop == nil || status.LastStop.Kind != runstate.KindOutOfMemory {
		t.Fatalf("status = %+v", status.LastStop)
	}
}
