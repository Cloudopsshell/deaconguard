package containers

import "testing"

func TestParseList(t *testing.T) {
	output := "4211|abc123|/shop|ghcr.io/acme/shop:1.4|sha256:aaa|docker\n" +
		"4211|abc123|/shop|ghcr.io/acme/shop:1.4|sha256:aaa|podman\n" +
		"0|stopped|/old|x|y|docker\n" +
		"\n" +
		"5100|def456|/default/web-5d9/nginx|docker.io/library/nginx:1.27|sha256:bbb|cri\n" +
		"garbage line\n"
	list := ParseList([]byte(output))
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	if list[0].Name != "default/web-5d9/nginx" || list[0].Runtime != "cri" || list[0].pid != 5100 {
		t.Errorf("cri container = %+v", list[0])
	}
	if list[1].Name != "shop" || list[1].Image != "ghcr.io/acme/shop:1.4" || list[1].ImageID != "sha256:aaa" {
		t.Errorf("docker container = %+v", list[1])
	}
}
