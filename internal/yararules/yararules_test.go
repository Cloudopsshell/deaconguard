package yararules

import (
	"archive/zip"
	"bytes"
	"testing"
)

const sample = `/*
 * YARA-Forge YARA Rule Package
 * https://github.com/YARAHQ/yara-forge
 *
 * Rule Package Information
 * Name: core
 * Creation Date: 2026-10-04
 * Number of Rules: 1
 */

rule Example_Webshell {
  meta:
    score = 75
  strings:
    $a = "eval($_POST"
  condition:
    $a
}
`

func packageWith(name, contents string) []byte {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, _ := writer.Create(name)
	file.Write([]byte(contents))
	writer.Close()
	return buffer.Bytes()
}

func TestExtractReadsTheRuleFileAndItsDate(t *testing.T) {
	input, err := Extract(packageWith("packages/core/yara-rules-core.yar", sample))
	if err != nil || input.Version != "YARA Forge core 2026-10-04" || string(input.Rules) != sample {
		t.Fatalf("Extract() = %q, %v", input.Version, err)
	}
}

func TestExtractRejectsOtherFiles(t *testing.T) {
	for name, archive := range map[string][]byte{
		"not a zip":        []byte("<html>rate limited</html>"),
		"no rule file":     packageWith("README.md", sample),
		"not YARA Forge":   packageWith("rules.yar", "rule a { condition: true }\nrule b { condition: true }"),
		"header but empty": packageWith("rules.yar", "/* YARA-Forge YARA Rule Package */"),
	} {
		if _, err := Extract(archive); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
