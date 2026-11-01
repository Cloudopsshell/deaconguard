package store

import (
	"slices"
	"testing"
)

func TestHostSummariesSayWhichAgentsToUpgrade(t *testing.T) {
	withTempDataDir(t)
	previous := ServerVersion
	t.Cleanup(func() { ServerVersion = previous })
	_, secret, err := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	machine, _, err := enrollWith(t, secret, "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	cluster, _, err := enrollWith(t, secret, "prod", KindCluster)
	if err != nil {
		t.Fatal(err)
	}
	upgrades := func() map[string]*Host {
		t.Helper()
		summaries, err := HostSummaries()
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]*Host{}
		for _, summary := range summaries {
			if summary.Agent.Upgrade != nil {
				found[summary.ID] = &summary.Host
				if summary.ID == machine.ID && (!slices.Equal(summary.Agent.Upgrade.Checks, []string{"changes"}) || summary.Agent.Upgrade.Command == "") {
					t.Errorf("machine: %+v", summary.Agent.Upgrade)
				}
				if summary.ID == cluster.ID && (len(summary.Agent.Upgrade.Checks) != 0 || summary.Agent.Upgrade.Command != "") {
					t.Errorf("cluster: %+v", summary.Agent.Upgrade)
				}
			}
		}
		return found
	}
	ServerVersion = "1.23.0"
	if found := upgrades(); len(found) != 2 {
		t.Fatalf("server 1.23.0: %d agents to upgrade, want 2", len(found))
	}
	ServerVersion = "1.21.0"
	if found := upgrades(); len(found) != 0 {
		t.Fatalf("server as new as its agents: %d to upgrade", len(found))
	}
}
