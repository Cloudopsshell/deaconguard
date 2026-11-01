package compliance

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestWriteMappingDocs writes the mapping as Markdown tables for the docs:
// DEACONGUARD_MAPPING_DOCS=file go test ./internal/compliance -run WriteMappingDocs
func TestWriteMappingDocs(t *testing.T) {
	path := os.Getenv("DEACONGUARD_MAPPING_DOCS")
	if path == "" {
		t.Skip("set DEACONGUARD_MAPPING_DOCS to write the tables")
	}
	var builder strings.Builder
	for _, framework := range frameworks {
		// The STIG mapping is per control; checks writes its table.
		if framework.ID == STIG {
			continue
		}
		evidence := map[string][]string{}
		for control, references := range mapping {
			for _, requirement := range references[framework.ID] {
				evidence[requirement] = append(evidence[requirement], strings.TrimPrefix(control, "CHECK-"))
			}
		}
		var requirements []string
		for requirement := range evidence {
			requirements = append(requirements, requirement)
		}
		sort.Slice(requirements, func(a, b int) bool { return naturalLess(requirements[a], requirements[b]) })
		fmt.Fprintf(&builder, "\n### %s\n\n| Requirement | | Evidence from |\n| --- | --- | --- |\n", framework.Name)
		for _, requirement := range requirements {
			controls := evidence[requirement]
			sort.Strings(controls)
			fmt.Fprintf(&builder, "| %s | %s | %s |\n", requirement, framework.Requirements[requirement], strings.Join(controls, ", "))
		}
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
