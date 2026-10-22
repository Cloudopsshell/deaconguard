package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMacAgentDaemon(t *testing.T) {
	plist := macAgentDaemon()
	for _, want := range []string{"<string>io.deaconguard.agent</string>", "<string>/usr/local/bin/deaconguard</string>", "<string>run</string>",
		"<key>SuccessfulExit</key>\n\t\t<false/>", "/usr/sbin", "/var/log/deaconguard-agent.log"} {
		if !strings.Contains(plist, want) {
			t.Errorf("the daemon lacks %q", want)
		}
	}
	if runtime.GOOS != "darwin" {
		return
	}
	path := filepath.Join(t.TempDir(), "agent.plist")
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v %s", err, output)
	}
}
