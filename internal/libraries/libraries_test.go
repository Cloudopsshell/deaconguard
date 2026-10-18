package libraries

import (
	"strings"
	"testing"
)

func record(path, contents string) string { return "\x1e" + path + "\n" + contents + "\n" }

func found(result Result) map[string]bool {
	m := make(map[string]bool)
	for _, library := range result.Libraries {
		m[library.Ecosystem+" "+library.Name+" "+library.Version] = true
	}
	return m
}

func TestParseEveryFormat(t *testing.T) {
	output := strings.Join([]string{
		record("/srv/app/package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"app"},
			"node_modules/lodash":{"version":"4.17.20"},
			"node_modules/@babel/core":{"version":"7.22.0"},
			"node_modules/a/node_modules/minimist":{"version":"1.2.5"},
			"node_modules/local":{"version":"file:../local"},
			"packages/workspace":{"link":true}}}`),
		record("/srv/old/package-lock.json", `{"lockfileVersion":1,"dependencies":{"express":{"version":"4.17.1","dependencies":{"qs":{"version":"6.7.0"}}},
			"gitdep":{"version":"git+https://example.com/x.git"}}}`),
		record("/srv/web/yarn.lock", "# yarn lockfile v1\n\n\"@types/node@^18\", \"@types/node@^18.1\":\n  version \"18.11.9\"\n  resolved \"https://x\"\n\naxios@0.21.1:\n  version \"0.21.1\"\n\nmine@file:../mine:\n  version \"1.0.0\"\n"),
		record("/srv/berry/yarn.lock", "__metadata:\n  version: 6\n\n\"debug@npm:^4.3.4\":\n  version: 4.3.4\n  resolution: \"debug@npm:4.3.4\"\n"),
		record("/srv/pn/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  semver@7.5.0:\n    resolution: {integrity: x}\n  '@scope/pkg@1.0.0(react@18.0.0)':\n    resolution: {integrity: y}\n"),
		record("/srv/pn6/pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /ws@8.0.0:\n    resolution: {integrity: z}\n"),
		record("/usr/lib/node_modules/npm/package.json", `{"name":"npm","version":"9.8.1"}`),
		record("/usr/lib/python3/dist-packages/Jinja2-3.1.2.dist-info/METADATA", "Metadata-Version: 2.1\nName: Jinja2\nVersion: 3.1.2\n\nVersion: 9.9.9 in the description\n"),
		record("/usr/local/lib/python3.12/dist-packages/simplejson-3.19.1.egg-info/PKG-INFO", "Metadata-Version: 1.1\nName: simplejson\nVersion: 3.19.1\n"),
		record("/srv/py/requirements.txt", "# pinned\nDjango==3.2.0\nrequests[socks] == 2.25.1 ; python_version > '3'\nflask>=2.0\n-r other.txt\nurllib3==1.26.4 \\\n    --hash=sha256:abc\n"),
		record("/srv/py/poetry.lock", "[[package]]\nname = \"PyYAML\"\nversion = \"5.3.1\"\n\n[package.dependencies]\nx = \"*\"\n\n[[package]]\nname = \"certifi\"\nversion = \"2020.12.5\"\n"),
		record("/srv/py/Pipfile.lock", `{"default":{"jinja2":{"version":"==2.10"}},"develop":{"pytest":{"version":"==6.0.0"}}}`),
		record("/srv/go/go.mod", "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/net v0.7.0\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0 // indirect\n)\n"),
		record("/srv/rb/Gemfile.lock", "GIT\n  remote: https://x\n  specs:\n    mine (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n"),
		record("/srv/rs/Cargo.lock", "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"git+https://x\"\n"),
		record("/srv/php/composer.lock", `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"v9.5.0"},{"name":"me/dev","version":"dev-main"}]}`),
		record("/srv/broken/package-lock.json", "{not json"),
	}, "")
	result := Parse([]byte(output))
	got := found(result)
	want := []string{
		"npm lodash 4.17.20", "npm @babel/core 7.22.0", "npm minimist 1.2.5", "npm express 4.17.1", "npm qs 6.7.0",
		"npm @types/node 18.11.9", "npm axios 0.21.1", "npm debug 4.3.4", "npm semver 7.5.0", "npm @scope/pkg 1.0.0",
		"npm ws 8.0.0", "npm npm 9.8.1",
		"PyPI jinja2 3.1.2", "PyPI django 3.2.0", "PyPI requests 2.25.1", "PyPI urllib3 1.26.4", "PyPI pyyaml 5.3.1",
		"PyPI certifi 2020.12.5", "PyPI jinja2 2.10", "PyPI pytest 6.0.0", "PyPI simplejson 3.19.1",
		"Go golang.org/x/net v0.7.0", "Go github.com/gin-gonic/gin v1.7.0",
		"RubyGems nokogiri 1.13.0", "RubyGems rack 2.2.3",
		"crates.io time 0.1.43", "crates.io app 0.1.0",
		"Packagist guzzlehttp/guzzle 7.4.0", "Packagist phpunit/phpunit 9.5.0",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %s", w)
		}
	}
	for _, unwanted := range []string{"npm local file:../local", "npm gitdep git+https://example.com/x.git", "npm mine 1.0.0",
		"PyPI flask 2.0", "PyPI jinja2 9.9.9", "RubyGems mine 1.0.0", "RubyGems racc 1.4", "crates.io gitdep 1.0.0", "Packagist me/dev dev-main", "npm app 0.0.0"} {
		if got[unwanted] {
			t.Errorf("unexpected %s", unwanted)
		}
	}
	if len(got) != len(want) {
		t.Errorf("found %d libraries, want %d: %v", len(got), len(want), got)
	}
	if result.Files != 17 {
		t.Errorf("files = %d, want 17", result.Files)
	}
	if len(result.Notes) != 1 || !strings.Contains(result.Notes[0], "/srv/broken/package-lock.json") {
		t.Errorf("notes = %v, want one about the broken lock file", result.Notes)
	}
}

func TestSameLibraryInSeveralFilesIsOneEntry(t *testing.T) {
	output := record("/a/package-lock.json", `{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`) +
		record("/b/package-lock.json", `{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`)
	result := Parse([]byte(output))
	if len(result.Libraries) != 1 || len(result.Libraries[0].Paths) != 2 {
		t.Fatalf("got %+v, want one lodash found in two files", result.Libraries)
	}
}

func TestNormalizePythonName(t *testing.T) {
	for input, want := range map[string]string{"Jinja2": "jinja2", "zope.interface": "zope-interface", "Foo__Bar": "foo-bar", "a-_.b": "a-b"} {
		if got := normalizePythonName(input); got != want {
			t.Errorf("normalizePythonName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCollectCommandIsFixedAndReadOnly(t *testing.T) {
	for _, forbidden := range []string{" rm ", " mv ", ">", "chmod", "curl", "wget", "eval"} {
		if strings.Contains(strings.ReplaceAll(CollectCommand, "2>/dev/null", ""), forbidden) {
			t.Errorf("CollectCommand contains %q", forbidden)
		}
	}
}
