package cli

import (
	"os"
	"strings"
	"testing"
)

func TestParseServerSetup(t *testing.T) {
	options, err := parseServerSetup([]string{"--listen", "10.0.0.5:9443", "--tls-cert", "/etc/ssl/dg.crt", "--tls-key", "/etc/ssl/dg.key", "--admin-user", "ops"})
	if err != nil || options.listen != "10.0.0.5:9443" || options.certificate != "/etc/ssl/dg.crt" || options.key != "/etc/ssl/dg.key" || options.adminUser != "ops" {
		t.Fatalf("parseServerSetup = %+v, %v", options, err)
	}
	for _, arguments := range [][]string{
		{"--listen"},
		{"--listen", "8443"},
		{"--listen", "127.0.0.1:8443"},
		{"--listen", "localhost:8443"},
		{"--tls-cert", "/etc/ssl/dg.crt"},
		{"--tls-cert", "dg.crt", "--tls-key", "dg.key"},
		{"--password", "secret"},
	} {
		if _, err := parseServerSetup(arguments); err == nil {
			t.Errorf("parseServerSetup(%q) accepted", arguments)
		}
	}
}

func TestParseAgentSetup(t *testing.T) {
	options, err := parseAgentSetup([]string{"--token-file", "/run/token", "--force"})
	if err != nil || options.tokenFile != "/run/token" || !options.force {
		t.Fatalf("parseAgentSetup = %+v, %v", options, err)
	}
	if _, err := parseAgentSetup([]string{"deaconguard1.abc"}); err == nil || !strings.Contains(err.Error(), "command line") {
		t.Fatalf("a token on the command line: %v", err)
	}
	if _, err := parseAgentSetup([]string{"--token-file"}); err == nil {
		t.Fatal("--token-file without a file was accepted")
	}
}

func TestServerDropInRoundTrip(t *testing.T) {
	if dropIn := renderServerDropIn(defaultServerListen, "", ""); dropIn != "" {
		t.Fatalf("the default settings need no drop-in, got %q", dropIn)
	}
	listen, certificate, key := parseServerDropIn("")
	if listen != defaultServerListen || certificate != "" || key != "" {
		t.Fatalf("no drop-in = %s %s %s", listen, certificate, key)
	}
	dropIn := renderServerDropIn("0.0.0.0:9443", "/etc/ssl/dg.crt", "/etc/ssl/dg.key")
	if !strings.Contains(dropIn, "\nExecStart=\nExecStart=/usr/bin/deaconguard serve --listen 0.0.0.0:9443 --tls-cert /etc/ssl/dg.crt --tls-key /etc/ssl/dg.key\n") {
		t.Fatalf("drop-in = %q", dropIn)
	}
	listen, certificate, key = parseServerDropIn(dropIn)
	if listen != "0.0.0.0:9443" || certificate != "/etc/ssl/dg.crt" || key != "/etc/ssl/dg.key" {
		t.Fatalf("parsed back %s %s %s", listen, certificate, key)
	}
}

func TestServerAddresses(t *testing.T) {
	if got := serverAddresses("10.0.0.5:8443"); len(got) != 1 || got[0] != "10.0.0.5" {
		t.Fatalf("serverAddresses for one address = %v", got)
	}
	got := serverAddresses("0.0.0.0:8443")
	if len(got) == 0 || got[0] == "" {
		t.Fatalf("serverAddresses for all addresses = %v", got)
	}
	for _, address := range got[1:] {
		if strings.HasPrefix(address, "127.") {
			t.Fatalf("listed a loopback address: %v", got)
		}
	}
}

func TestSetupNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	for _, target := range []string{"server", "agent"} {
		var output, diagnostics strings.Builder
		if code := Run([]string{"setup", target}, nil, &output, &diagnostics); code == 0 || !strings.Contains(diagnostics.String(), "sudo") {
			t.Errorf("setup %s without root: code %d, %s", target, code, diagnostics.String())
		}
	}
}
