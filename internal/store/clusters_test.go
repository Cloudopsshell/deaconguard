package store

import (
	"strings"
	"testing"
	"time"
)

func TestNodesFollowTheirCluster(t *testing.T) {
	withTempDataDir(t)
	_, secret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	cluster, _, _ := enrollWith(t, secret, "prod", KindCluster)
	one, _, _ := enrollWith(t, secret, "node-1", "")
	two, _, _ := enrollWith(t, secret, "node-2", "")
	server, _, _ := enrollWith(t, secret, "web-1", "")
	if err := LinkClusterNodes(cluster.ID, []string{"node-1", "node-2"}); err != nil {
		t.Fatal(err)
	}
	if err := SetLiveEnabled(cluster.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := SetHostTags(cluster.ID, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetAutoScanContainers(cluster.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := SetExcluded(two.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := SetExcluded(server.ID, true); err == nil {
		t.Error("a machine of its own was excluded")
	}
	for _, c := range []struct {
		host       Host
		live, auto bool
		tags       string
	}{{one, true, true, "prod"}, {two, false, false, "prod"}, {server, false, false, ""}} {
		live, _, _ := LiveSettings(c.host.ID)
		host, _ := GetHost(c.host.ID)
		tags, _ := HostTags(c.host.ID)
		if live != c.live || host.AutoScanContainers != c.auto || strings.Join(tags, ",") != c.tags {
			t.Errorf("%s: live %t, auto %t, tags %v", host.Address, live, host.AutoScanContainers, tags)
		}
	}
	one, _ = GetHost(one.ID)
	two, _ = GetHost(two.ID)
	if err := NodeSettingError(one); err == nil || !strings.Contains(err.Error(), "follows the settings of its cluster prod") {
		t.Errorf("node setting: %v", err)
	}
	schedule := Schedule{HostIDs: []string{cluster.ID}}
	if !schedule.Covers(one) || schedule.Covers(two) || schedule.Covers(server) || (Schedule{AllHosts: true}).Covers(two) {
		t.Error("a cluster's schedule covers its nodes but the excluded one")
	}
	// Turning it on for all turns it on for the cluster, so its nodes.
	SetLiveEnabled(cluster.ID, false)
	if _, err := SetLiveAll(true); err != nil {
		t.Fatal(err)
	}
	if live, _, _ := LiveSettings(one.ID); !live {
		t.Error("turned on for all, not for the node")
	}

	// node-2 leaves the cluster; its agent goes quiet. It stays linked,
	// marked, until it has been gone three days.
	db, _ := database()
	long := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	db.Exec("UPDATE agents SET last_seen_at = ? WHERE host_id = ?", long, two.ID)
	if err := LinkClusterNodes(cluster.ID, []string{"node-1"}); err != nil {
		t.Fatal(err)
	}
	if host, _ := GetHost(two.ID); host.ClusterID != cluster.ID || host.LeftClusterAt == "" {
		t.Fatalf("gone node: %+v", host)
	}
	if removed, _ := RemoveGoneNodes(time.Now()); len(removed) != 0 {
		t.Fatalf("removed too soon: %v", removed)
	}
	if removed, _ := RemoveGoneNodes(time.Now().Add(NodeGoneAfter + time.Hour)); len(removed) != 1 || removed[0].ID != two.ID {
		t.Fatalf("removed: %v", removed)
	}
	if _, err := GetHost(one.ID); err != nil {
		t.Error("node-1 removed")
	}
}

func TestSchemaV33MovesNodeSettingsToTheCluster(t *testing.T) {
	withTempDataDir(t)
	_, secret, _ := CreateEnrollmentToken("https://server:8444", "admin", TokenOptions{Reusable: true})
	cluster, _, _ := enrollWith(t, secret, "prod", KindCluster)
	one, _, _ := enrollWith(t, secret, "node-1", "")
	two, _, _ := enrollWith(t, secret, "node-2", "")
	LinkClusterNodes(cluster.ID, []string{"node-1", "node-2"})
	// As 1.27 left them: settings on one node only.
	db, _ := database()
	db.Exec("UPDATE hosts SET live_enabled = 1, auto_scan_containers = 1 WHERE id = ?", one.ID)
	db.Exec("INSERT INTO host_tags (host_id, tag) VALUES (?, 'team:web')", two.ID)
	schedule, err := SaveSchedule(Schedule{Name: "Nightly", Enabled: true, Checks: []string{CheckPackages}, HostIDs: []string{one.ID, two.ID},
		Days: []int{1}, Time: "02:00", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	_, statements, _ := strings.Cut(schemaV33, "ALTER TABLE hosts ADD COLUMN left_cluster_at TEXT NOT NULL DEFAULT '';")
	if err := execInTx(db, statements); err != nil {
		t.Fatal(err)
	}
	if err := moveNodeSchedules(db); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{cluster.ID, one.ID, two.ID} {
		live, _, _ := LiveSettings(id)
		host, _ := GetHost(id)
		tags, _ := HostTags(id)
		if !live || !host.AutoScanContainers || strings.Join(tags, ",") != "team:web" {
			t.Errorf("%s: live %t, auto %t, tags %v", host.Address, live, host.AutoScanContainers, tags)
		}
	}
	if moved, _ := GetSchedule(schedule.ID); strings.Join(moved.HostIDs, ",") != cluster.ID {
		t.Errorf("schedule hosts: %v", moved.HostIDs)
	}
}
