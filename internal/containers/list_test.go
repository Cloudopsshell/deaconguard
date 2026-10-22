package containers

import (
	"reflect"
	"testing"
)

func TestParseList(t *testing.T) {
	output := "4211|abc123|/shop|ghcr.io/acme/shop:1.4|sha256:aaa|docker\n" +
		"4211|abc123|/shop|ghcr.io/acme/shop:1.4|sha256:aaa|podman\n" +
		"0|stopped|/old|x|y|docker\n" +
		"\n" +
		"5100|def456|/default/web-5d9/nginx|docker.io/library/nginx:1.27|sha256:bbb|cri\n" +
		"garbage line\n"
	list := ParseList([]byte(output))
	if len(list) != 3 {
		t.Fatalf("list = %+v", list)
	}
	if list[0].Name != "default/web-5d9/nginx" || list[0].Runtime != "cri" || list[0].pid != 5100 || list[0].State != "running" {
		t.Errorf("cri container = %+v", list[0])
	}
	if list[1].Name != "shop" || list[1].Image != "ghcr.io/acme/shop:1.4" || list[1].ImageID != "sha256:aaa" {
		t.Errorf("docker container = %+v", list[1])
	}
	if list[2].Name != "old" || list[2].Running() || list[2].State != "stopped" {
		t.Errorf("stopped container = %+v", list[2])
	}
}

// The details, as Docker 29, Podman 4 and crictl print them.
func TestParseListDetails(t *testing.T) {
	output := "538|8f99|/web|nginx:1.18|sha256:aaa|docker|running|2026-10-19T20:39:02.42647705Z|2026-10-22T20:01:44.4202495Z|2026-10-22T20:01:44.200463166Z|0|2||true|bridge|127.0.0.1:8080->80/tcp 0.0.0.0:8443->443/tcp |[\"/docker-entrypoint.sh\"] [\"nginx\",\"-g\",\"daemon off;\"]\n" +
		"0|d72f|/job|alpine:3.20|sha256:bbb|docker|exited|2026-10-22T20:01:50.982170461Z|2026-10-22T20:01:51.025664045Z|2026-10-22T20:01:51.101617753Z|3|0|1001:1001|false|bridge||null [\"sh\",\"-c\",\"echo a|b\"]\n" +
		"77|aa11|/pod|quay.io/x:1|sha256:ccc|podman|running|2026-10-22 21:21:00.123456789 +0000 UTC|2026-10-22 21:21:01.5 +0000 UTC|0001-01-01 00:00:00 +0000 UTC|0|0|app|false|slirp4netns||\"/entrypoint\" [\"serve\"]\n" +
		"901|cc22|/kube-system/coredns-7/coredns|registry.k8s.io/coredns:v1.11|sha256:ddd|cri|CONTAINER_RUNNING|1729631000000000000|1729631001000000000|0|0|3|||||\n"
	list := ParseList([]byte(output))
	if len(list) != 4 {
		t.Fatalf("list = %+v", list)
	}
	byName := map[string]Container{}
	for _, c := range list {
		byName[c.Name] = c
	}
	web := byName["web"]
	if web.State != "running" || web.Created != "2026-10-19T20:39:02Z" || web.StartedAt != "2026-10-22T20:01:44Z" || web.FinishedAt != "" ||
		web.Restarts != 2 || !web.Privileged || web.Network != "bridge" || web.Command != "/docker-entrypoint.sh nginx -g daemon off;" ||
		!reflect.DeepEqual(web.Ports, []string{"127.0.0.1:8080->80/tcp", "0.0.0.0:8443->443/tcp"}) {
		t.Errorf("web = %+v", web)
	}
	job := byName["job"]
	if job.State != "exited" || job.ExitCode != 3 || job.User != "1001:1001" || job.Command != "sh -c echo a|b" || job.FinishedAt != "2026-10-22T20:01:51Z" {
		t.Errorf("job = %+v", job)
	}
	pod := byName["pod"]
	if pod.Created != "2026-10-22T21:21:00Z" || pod.StartedAt != "2026-10-22T21:21:01Z" || pod.Command != "/entrypoint serve" || pod.User != "app" {
		t.Errorf("podman = %+v", pod)
	}
	dns := byName["kube-system/coredns-7/coredns"]
	if dns.State != "running" || dns.Restarts != 3 || dns.Created != "2024-10-22T21:03:20Z" {
		t.Errorf("cri = %+v", dns)
	}
	if list[len(list)-1].Name != "job" {
		t.Errorf("stopped containers should come last: %+v", list)
	}
}
