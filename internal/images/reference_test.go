package images

import "testing"

func TestParseReference(t *testing.T) {
	for input, want := range map[string]Reference{
		"nginx":                                   {Registry: dockerHub, Repository: "library/nginx", Tag: "latest"},
		"nginx:1.27":                              {Registry: dockerHub, Repository: "library/nginx", Tag: "1.27"},
		"docker.io/bitnami/redis:7.2":             {Registry: dockerHub, Repository: "bitnami/redis", Tag: "7.2"},
		"ghcr.io/acme/shop:4.2":                   {Registry: "ghcr.io", Repository: "acme/shop", Tag: "4.2"},
		"localhost:5000/team/app":                 {Registry: "localhost:5000", Repository: "team/app", Tag: "latest"},
		"registry.example.com:5000/a/b/c:v1-rc.2": {Registry: "registry.example.com:5000", Repository: "a/b/c", Tag: "v1-rc.2"},
		"alpine@sha256:" + sixtyFour:              {Registry: dockerHub, Repository: "library/alpine", Digest: "sha256:" + sixtyFour},
		"quay.io/org/app:1@sha256:" + sixtyFour:   {Registry: "quay.io", Repository: "org/app", Tag: "1", Digest: "sha256:" + sixtyFour},
	} {
		got, err := ParseReference(input)
		if err != nil || got != want {
			t.Errorf("ParseReference(%q) = %+v, %v; want %+v", input, got, err, want)
		}
	}
	for _, bad := range []string{"", "UPPER/case", "nginx:bad tag", "a@sha256:short", "../etc", "ghcr.io/acme/shop:" + string(make([]byte, 200))} {
		if _, err := ParseReference(bad); err == nil {
			t.Errorf("ParseReference(%q) accepted", bad)
		}
	}
	ref, _ := ParseReference("nginx:1.27")
	if ref.String() != "nginx:1.27" {
		t.Errorf("String = %q", ref.String())
	}
}

const sixtyFour = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRegistryHost(t *testing.T) {
	for input, want := range map[string]string{
		"docker.io":                            dockerHub,
		"https://GHCR.io/":                     "ghcr.io",
		"registry.example.com:5000":            "registry.example.com:5000",
		" quay.io ":                            "quay.io",
		"123.dkr.ecr.eu-north-1.amazonaws.com": "123.dkr.ecr.eu-north-1.amazonaws.com",
	} {
		if got, err := RegistryHost(input); err != nil || got != want {
			t.Errorf("RegistryHost(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "ghcr.io/acme", "../etc", "a b"} {
		if _, err := RegistryHost(input); err == nil {
			t.Errorf("RegistryHost(%q) accepted", input)
		}
	}
}
