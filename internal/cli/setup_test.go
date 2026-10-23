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
	if dropIn := renderServerDropIn(defaultServerListen, "", "", ""); dropIn != "" {
		t.Fatalf("the default settings need no drop-in, got %q", dropIn)
	}
	listen, agentListen, certificate, key := parseServerDropIn("")
	if listen != defaultServerListen || agentListen != "" || certificate != "" || key != "" {
		t.Fatalf("no drop-in = %s %s %s %s", listen, agentListen, certificate, key)
	}
	dropIn := renderServerDropIn("0.0.0.0:9443", "0.0.0.0:8444", "/etc/ssl/dg.crt", "/etc/ssl/dg.key")
	if !strings.Contains(dropIn, "\nExecStart=\nExecStart=/usr/bin/deaconguard serve --listen 0.0.0.0:9443 --agent-listen 0.0.0.0:8444 --tls-cert /etc/ssl/dg.crt --tls-key /etc/ssl/dg.key\n") {
		t.Fatalf("drop-in = %q", dropIn)
	}
	listen, agentListen, certificate, key = parseServerDropIn(dropIn)
	if listen != "0.0.0.0:9443" || agentListen != "0.0.0.0:8444" || certificate != "/etc/ssl/dg.crt" || key != "/etc/ssl/dg.key" {
		t.Fatalf("parsed back %s %s %s %s", listen, agentListen, certificate, key)
	}
	if dropIn := renderServerDropIn(defaultServerListen, "0.0.0.0:8444", "", ""); !strings.Contains(dropIn, "--listen 0.0.0.0:8443 --agent-listen 0.0.0.0:8444\n") {
		t.Fatalf("agent port alone = %q", dropIn)
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

func TestChooseAgentListen(t *testing.T) {
	free := func(string) bool { return true }
	busy := func(string) bool { return false }
	cases := []struct {
		name, requested, saved string
		wasOff                 bool
		listen                 string
		free                   func(string) bool
		want                   string
		off                    bool
		note                   string
	}{
		{"new server", "", "", false, "0.0.0.0:8443", free, "0.0.0.0:8444", false, "port of their own"},
		{"upgrade without one", "", "", false, "0.0.0.0:8443", free, "0.0.0.0:8444", false, "move to it by themselves"},
		{"kept", "", "0.0.0.0:9444", false, "0.0.0.0:8443", free, "0.0.0.0:9444", false, ""},
		{"asked for", "10.0.0.5:8444", "", true, "0.0.0.0:8443", free, "10.0.0.5:8444", false, ""},
		{"turned off now", "off", "0.0.0.0:8444", false, "0.0.0.0:8443", free, "", true, ""},
		{"turned off before", "", "", true, "0.0.0.0:8443", free, "", true, ""},
		{"dashboard on loopback", "", "", false, "127.0.0.1:8443", free, "", false, ""},
		{"port taken", "", "", false, "0.0.0.0:8443", busy, "", false, "in use"},
	}
	for _, c := range cases {
		got, off, note := chooseAgentListen(c.requested, c.saved, c.wasOff, c.listen, c.free)
		if got != c.want || off != c.off || (c.note == "") != (note == "") || !strings.Contains(note, c.note) {
			t.Errorf("%s: %q, %v, %q", c.name, got, off, note)
		}
	}
}
