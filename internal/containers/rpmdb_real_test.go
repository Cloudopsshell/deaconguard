package containers

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// TestRealRPMDB compares the reader with rpm -qa on a real database, when
// DEACONGUARD_TEST_RPMDB points at a directory with rpmdb.sqlite and
// expected.txt.
func TestRealRPMDB(t *testing.T) {
	dir := os.Getenv("DEACONGUARD_TEST_RPMDB")
	if dir == "" {
		t.Skip("set DEACONGUARD_TEST_RPMDB")
	}
	data, err := os.ReadFile(dir + "/rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	got, err := rpmQueryFromSQLite(data)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		lines = append(lines, strings.TrimSuffix(line, "\t(none)"))
	}
	sort.Strings(lines)
	expected, _ := os.ReadFile(dir + "/expected.txt")
	want := strings.Split(strings.TrimSpace(string(expected)), "\n")
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %d packages, rpm -qa has %d; first: %q vs %q", len(lines), len(want), lines[0], want[0])
	}
}
