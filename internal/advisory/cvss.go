package advisory

import (
	"strconv"
	"strings"
)

// parseCVSS checks a CVSS v3 base score and vector from a feed. A score
// outside 0.1 to 10, or a vector that isn't CVSS v3, is dropped rather than
// shown.
func parseCVSS(score, vector string) (float64, string) {
	value, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil || value < 0.1 || value > 10 {
		return 0, ""
	}
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.") || len(vector) > 200 {
		vector = ""
	}
	return value, vector
}
