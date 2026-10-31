package containers

import (
	"reflect"
	"testing"
)

// A Kubernetes container's mounts, as /proc/PID/mountinfo shows them: an
// overlay root, an emptyDir on the node's disk, a memory emptyDir (tmpfs),
// a PersistentVolume and the service account token, which are left out.
const containerMounts = `1501 1400 0:310 / / rw,relatime master:500 - overlay overlay rw,lowerdir=/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/41/fs,upperdir=/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/97/fs,workdir=/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/97/work
1502 1501 0:320 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1510 1501 8:1 /var/lib/kubelet/pods/5f1c/volumes/kubernetes.io~empty-dir/scratch /tmp rw,relatime - ext4 /dev/sda1 rw
1511 1501 0:330 / /cache rw,relatime - tmpfs tmpfs rw,size=65536k
1512 1501 8:1 /var/lib/rancher/k3s/storage/pvc-1_shop_data /var/lib/data rw,relatime - ext4 /dev/sda1 rw
1513 1501 0:331 / /var/run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=4096k
`

// The node's own mounts: its disk, and kubelet's tmpfs volumes.
const hostMounts = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
900 22 0:330 / /var/lib/kubelet/pods/5f1c/volumes/kubernetes.io~empty-dir/cache rw,relatime shared:400 - tmpfs tmpfs rw,size=65536k
901 22 0:331 / /var/lib/kubelet/pods/5f1c/volumes/kubernetes.io~projected/kube-api-access-x rw,relatime shared:401 - tmpfs tmpfs rw,size=4096k
`

func TestWritableDirsFindsTheUpperLayerAndEmptyDirs(t *testing.T) {
	got := writableDirs(parseMountInfo(containerMounts), parseMountInfo(hostMounts))
	want := []WritableDir{
		{HostPath: "/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/97/fs", Path: "/"},
		{HostPath: "/var/lib/kubelet/pods/5f1c/volumes/kubernetes.io~empty-dir/cache", Path: "/cache"},
		{HostPath: "/var/lib/kubelet/pods/5f1c/volumes/kubernetes.io~empty-dir/scratch", Path: "/tmp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("writableDirs() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestWritableDirsWithoutOverlay(t *testing.T) {
	// btrfs and ZFS drivers have no upper layer to find.
	mounts := parseMountInfo("1 0 0:40 /subvol / rw - btrfs /dev/sdb rw\n")
	if got := writableDirs(mounts, parseMountInfo(hostMounts)); len(got) != 0 {
		t.Fatalf("writableDirs() = %+v", got)
	}
}

func TestMountPathsAreUnescapedAndChecked(t *testing.T) {
	mounts := parseMountInfo(`5 1 0:9 / / rw - overlay overlay rw,upperdir=/var/lib/my\040docker/overlay2/abc/diff,workdir=/w` + "\n")
	if got := mounts[0].option("upperdir"); got != "/var/lib/my docker/overlay2/abc/diff" {
		t.Fatalf("upperdir = %q", got)
	}
	for path, ok := range map[string]bool{
		"/var/lib/docker/overlay2/abc/diff": true, "relative/diff": false, "/var/lib/../etc": false, "/": false, "/a\nb": false,
	} {
		if validHostPath(path) != ok {
			t.Errorf("validHostPath(%q) = %v", path, !ok)
		}
	}
	if got := unescapeMount(`a\134b\05`); got != `a\b\05` {
		t.Fatalf("unescapeMount() = %q", got)
	}
}

func TestProcessesAreNamedAfterTheirContainer(t *testing.T) {
	list := []Writable{
		{ID: "4c01db0b339c4e0fa4e8f1a7b3b5d3a8a7c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5", Name: "shop/web-7d9/nginx"},
		{ID: "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0", Name: "redis"},
	}
	k8s := "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod5f1c.slice/cri-containerd-4c01db0b339c4e0fa4e8f1a7b3b5d3a8a7c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5.scope\n"
	docker := "12:pids:/docker/9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0\n"
	if got := containerInCgroup(k8s, list); got != "shop/web-7d9/nginx" {
		t.Fatalf("k8s = %q", got)
	}
	if got := containerInCgroup(docker, list); got != "redis" {
		t.Fatalf("docker = %q", got)
	}
	if got := containerInCgroup("0::/system.slice/sshd.service\n", list); got != "" {
		t.Fatalf("host = %q", got)
	}
}
