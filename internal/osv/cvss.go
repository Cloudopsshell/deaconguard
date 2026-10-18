package osv

import (
	"math"
	"strings"
)

// cvss3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector, as
// the FIRST specification defines it. ok is false for anything else.
func cvss3BaseScore(vector string) (score float64, ok bool) {
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, false
	}
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/")[1:] {
		name, value, found := strings.Cut(part, ":")
		if !found {
			return 0, false
		}
		metrics[name] = value
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	value := make(map[string]float64)
	for name, table := range weights {
		weight, found := table[metrics[name]]
		if !found {
			return 0, false
		}
		value[name] = weight
	}
	changed := metrics["S"] == "C"
	if metrics["S"] != "U" && !changed {
		return 0, false
	}
	privileges := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		privileges = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, found := privileges[metrics["PR"]]
	if !found {
		return 0, false
	}
	iss := 1 - (1-value["C"])*(1-value["I"])*(1-value["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * value["AV"] * value["AC"] * pr * value["UI"]
	if impact <= 0 {
		return 0, true
	}
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(math.Min(impact+exploitability, 10)), true
}

// roundUp is the specification's Roundup: the smallest number with one
// decimal that is at least the input.
func roundUp(input float64) float64 {
	integer := int(math.Round(input * 100000))
	if integer%10000 == 0 {
		return float64(integer) / 100000
	}
	return (math.Floor(float64(integer)/10000) + 1) / 10
}

// severityOfScore is the CVSS qualitative rating.
func severityOfScore(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return "UNKNOWN"
}

// CVSS3 is a record's CVSS v3 base score and vector, if it has one.
func CVSS3(record Vulnerability) (float64, string, bool) {
	for _, severity := range record.Severity {
		if severity.Type == "CVSS_V3" {
			if score, ok := cvss3BaseScore(severity.Score); ok {
				return score, severity.Score, true
			}
		}
	}
	return 0, "", false
}

// SeverityOfScore is the CVSS qualitative rating of a base score.
func SeverityOfScore(score float64) string { return severityOfScore(score) }
