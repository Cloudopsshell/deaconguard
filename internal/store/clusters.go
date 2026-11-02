package store

import (
	"database/sql"
	"fmt"
	"slices"
	"time"
)

// A Kubernetes cluster is managed as one: its live detection, its scanning
// when it changes and its tags are set on the cluster, and every node linked
// to it follows them, nodes that join later included. The nodes' own columns
// hold copies, kept in step by syncNodes, so everything that reads a host's
// settings reads a node's like any other host's. An excluded node has live
// detection and scanning when it changes off, and is left out of the
// cluster's scans; it keeps the cluster's tags.

// FollowsCluster is the error for changing a setting on a node.
type FollowsCluster struct{ Node, Cluster string }

func (err FollowsCluster) Error() string {
	return fmt.Sprintf("%s follows the settings of its cluster %s: change them on the cluster", err.Node, err.Cluster)
}

// NodeSettingError returns FollowsCluster when host is a node.
func NodeSettingError(host Host) error {
	if !host.IsNode() {
		return nil
	}
	cluster, err := GetHost(host.ClusterID)
	if err != nil {
		return FollowsCluster{Node: host.Address, Cluster: host.ClusterID}
	}
	return FollowsCluster{Node: host.Address, Cluster: cluster.Address}
}

type execer interface {
	Exec(query string, arguments ...any) (sql.Result, error)
}

// syncNodes copies a cluster's settings to its nodes.
func syncNodes(tx execer, clusterID string) error {
	if _, err := tx.Exec(`UPDATE hosts SET
		live_enabled = CASE WHEN excluded = 1 THEN 0 ELSE (SELECT c.live_enabled FROM hosts c WHERE c.id = ?) END,
		auto_scan_containers = CASE WHEN excluded = 1 THEN 0 ELSE (SELECT c.auto_scan_containers FROM hosts c WHERE c.id = ?) END
		WHERE cluster_id = ?`, clusterID, clusterID, clusterID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM host_tags WHERE host_id IN (SELECT id FROM hosts WHERE cluster_id = ?)", clusterID); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO host_tags (host_id, tag)
		SELECT n.id, t.tag FROM hosts n JOIN host_tags t ON t.host_id = ? WHERE n.cluster_id = ?`, clusterID, clusterID)
	return err
}

// syncIfCluster copies a host's settings to its nodes when it's a cluster.
func syncIfCluster(hostID string) error {
	db, err := database()
	if err != nil {
		return err
	}
	return syncNodes(db, hostID)
}

// syncAllClusters copies every cluster's settings to its nodes.
func syncAllClusters() error {
	db, err := database()
	if err != nil {
		return err
	}
	rows, err := db.Query("SELECT id FROM hosts WHERE kind = ?", KindCluster)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := syncNodes(db, id); err != nil {
			return err
		}
	}
	return nil
}

// SetExcluded leaves a node out of its cluster's scans and live detection,
// or brings it back.
func SetExcluded(nodeID string, excluded bool) (Host, error) {
	host, err := GetHost(nodeID)
	if err != nil {
		return Host{}, err
	}
	if !host.IsNode() {
		return Host{}, fmt.Errorf("%s isn't a node of a cluster: only nodes can be excluded", host.Address)
	}
	db, err := database()
	if err != nil {
		return Host{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return Host{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE hosts SET excluded = ? WHERE id = ?", excluded, nodeID); err != nil {
		return Host{}, err
	}
	if err := syncNodes(tx, host.ClusterID); err != nil {
		return Host{}, err
	}
	if err := tx.Commit(); err != nil {
		return Host{}, err
	}
	return GetHost(nodeID)
}

// ClusterNodes lists a cluster's nodes.
func ClusterNodes(clusterID string) ([]Host, error) {
	hosts, err := ListHosts()
	if err != nil {
		return nil, err
	}
	var nodes []Host
	for _, host := range hosts {
		if host.ClusterID == clusterID {
			nodes = append(nodes, host)
		}
	}
	return nodes, nil
}

// NodeGoneAfter is how long a node the cluster no longer lists, and whose
// agent has gone quiet, is kept before it's removed.
const NodeGoneAfter = 3 * 24 * time.Hour

// RemoveGoneNodes removes the nodes that left their cluster before
// now-NodeGoneAfter and whose agents haven't been heard from since.
func RemoveGoneNodes(now time.Time) ([]Host, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-NodeGoneAfter).UTC().Format(time.RFC3339)
	rows, err := db.Query(`SELECT h.id FROM hosts h JOIN agents a ON a.host_id = h.id
		WHERE h.cluster_id != '' AND h.left_cluster_at != '' AND h.left_cluster_at <= ? AND a.last_seen_at <= ?`, cutoff, cutoff)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	var removed []Host
	for _, id := range ids {
		host, err := RemoveHost(id)
		if err != nil {
			return removed, err
		}
		removed = append(removed, host)
	}
	return removed, nil
}

// moveNodeSchedules points schedules that named a cluster's node at the
// cluster instead, so the cluster and all its nodes are scanned (1.28.0).
func moveNodeSchedules(db *sql.DB) error {
	clusters := map[string]string{}
	rows, err := db.Query("SELECT id, cluster_id FROM hosts WHERE cluster_id != ''")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, cluster string
		if err := rows.Scan(&id, &cluster); err != nil {
			rows.Close()
			return err
		}
		clusters[id] = cluster
	}
	rows.Close()
	if len(clusters) == 0 {
		return nil
	}
	rows, err = db.Query("SELECT id, host_ids FROM schedules WHERE all_hosts = 0")
	if err != nil {
		return err
	}
	updates := map[string]string{}
	for rows.Next() {
		var id, hosts string
		if err := rows.Scan(&id, &hosts); err != nil {
			rows.Close()
			return err
		}
		changed := false
		var moved []string
		for _, host := range decodeChecks(hosts) {
			if cluster, ok := clusters[host]; ok {
				host, changed = cluster, true
			}
			if !slices.Contains(moved, host) {
				moved = append(moved, host)
			}
		}
		if changed {
			updates[id] = encodeChecks(moved)
		}
	}
	rows.Close()
	for id, hosts := range updates {
		if _, err := db.Exec("UPDATE schedules SET host_ids = ? WHERE id = ?", hosts, id); err != nil {
			return err
		}
	}
	return nil
}
