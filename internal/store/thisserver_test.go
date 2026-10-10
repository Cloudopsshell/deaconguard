package store

import (
	"testing"
)

func TestAdoptThisServerMovesTheLocalHostsHistory(t *testing.T) {
	withTempDataDir(t)
	local, err := AddLocalHost("server.example", "deaconguard")
	if err != nil {
		t.Fatal(err)
	}
	other := addTestHost(t, "web-01.example", TransportAgent)
	record, err := CreateScan(local, []string{CheckPackages})
	if err != nil {
		t.Fatal(err)
	}
	if err := CompleteScan(record.ID, map[string]any{"checks_run": []string{CheckPackages}, "findings": []map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	Log(LogServer, local.ID, LogInfo, "Scan of server.example finished")
	schedule, err := SaveSchedule(Schedule{Name: "Nightly", Enabled: true, Checks: []string{CheckPackages}, HostIDs: []string{local.ID, other.ID},
		Days: []int{1}, Time: "02:00", Timezone: "UTC", CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}

	agent := addTestHost(t, "server.example", TransportAgent)
	if _, err := AdoptThisServer(local.ID); err == nil {
		t.Fatal("a local host was adopted as the server's agent host")
	}
	merged, err := AdoptThisServer(agent.ID)
	if err != nil || !merged {
		t.Fatalf("AdoptThisServer() = %v, %v", merged, err)
	}
	if _, err := GetHost(local.ID); err == nil {
		t.Fatal("the local host still exists")
	}
	if scans, err := ListScans(agent.ID, 10); err != nil || len(scans) != 1 || scans[0].ID != record.ID {
		t.Fatalf("agent host's scans = %+v, %v", scans, err)
	}
	if entries, _, _ := Logs(LogQuery{HostID: agent.ID}); len(entries) != 1 {
		t.Fatalf("agent host's log = %+v", entries)
	}
	moved, _ := GetSchedule(schedule.ID)
	if len(moved.HostIDs) != 2 || moved.HostIDs[0] != agent.ID || moved.HostIDs[1] != other.ID {
		t.Fatalf("schedule hosts = %v", moved.HostIDs)
	}
	summaries, err := HostSummaries()
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range summaries {
		if summary.ThisServer != (summary.ID == agent.ID) {
			t.Errorf("%s: this_server = %v", summary.Address, summary.ThisServer)
		}
	}
	// Running it again, as an upgrade does, changes nothing more.
	if merged, err := AdoptThisServer(agent.ID); err != nil || merged {
		t.Fatalf("second AdoptThisServer() = %v, %v", merged, err)
	}
}
