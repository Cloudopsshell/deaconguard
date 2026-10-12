package report

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"strings"
	"time"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
)

//go:embed templates/report.html.tmpl
var templates embed.FS

// maxListedVulnerabilities bounds how many vulnerabilities without a fix the
// PDF and HTML list; the other formats have them all.
const maxListedVulnerabilities = 200

// Link is a download offered at the top of a shared report.
type Link struct {
	URL   template.URL
	Label string
}

// view is what the HTML and PDF reports show, worked out once.
type view struct {
	R                   Report
	Fingerprint         string
	Logo                template.URL
	Generated, Scanned  string
	CheckNames          string
	Failed, Accepted    []audit.Control
	Passed, Other       []audit.Control
	Vulnerabilities     []Vulnerability
	MoreVulnerabilities int
	Downloads           []Link
}

func newView(report Report, fingerprint string) view {
	v := view{R: report, Fingerprint: FormatFingerprint(fingerprint), Generated: formatDate(report.GeneratedAt.Format(time.RFC3339)),
		Scanned: formatDate(report.StartedAt)}
	if logo := logoDataURI(report.Branding); logo != "" {
		v.Logo = template.URL(logo)
	}
	names := map[string]string{}
	for _, definition := range checks.Definitions() {
		names[definition.ID] = definition.Name
	}
	var checkNames []string
	for _, id := range report.Checks {
		checkNames = append(checkNames, names[id])
	}
	v.CheckNames = strings.Join(checkNames, ", ")
	if report.Audit != nil {
		for _, control := range report.Audit.Controls {
			switch control.Status {
			case checks.ControlFail:
				v.Failed = append(v.Failed, control)
			case audit.Accepted:
				v.Accepted = append(v.Accepted, control)
			case checks.ControlPass:
				v.Passed = append(v.Passed, control)
			default:
				v.Other = append(v.Other, control)
			}
		}
	}
	waiting := 0
	for _, vulnerability := range report.Vulnerabilities {
		if actionable(vulnerability.Fix) || waiting < maxListedVulnerabilities {
			if !actionable(vulnerability.Fix) {
				waiting++
			}
			v.Vulnerabilities = append(v.Vulnerabilities, vulnerability)
			continue
		}
		v.MoreVulnerabilities++
	}
	return v
}

func logoDataURI(branding Branding) string {
	if len(branding.Logo) == 0 || (branding.LogoType != "image/png" && branding.LogoType != "image/jpeg") {
		return ""
	}
	return "data:" + branding.LogoType + ";base64," + base64.StdEncoding.EncodeToString(branding.Logo)
}

func formatDate(value string) string {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return parsed.UTC().Format("2 January 2006, 15:04 UTC")
}

func formatBytes(value int64) string {
	if value <= 0 {
		return "—"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	size, unit := float64(value), 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if size >= 10 || unit == 0 {
		return fmt.Sprintf("%.0f %s", size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func formatUptime(seconds int64) string {
	days, hours := seconds/86400, (seconds%86400)/3600
	if days > 0 {
		return fmt.Sprintf("%d days, %d h", days, hours)
	}
	return fmt.Sprintf("%d h %d min", hours, (seconds%3600)/60)
}

func runsOn(virtualization string) string {
	if virtualization == "" || virtualization == "none" {
		return "physical hardware"
	}
	return virtualization
}

func join(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	return strings.Join(values, ", ")
}

var page = template.Must(template.New("report.html.tmpl").Funcs(template.FuncMap{
	"add":    func(a, b int) int { return a + b },
	"total":  func(c audit.Category) int { return c.Passed + c.Failed + c.Accepted + c.NotApplicable + c.Unknown },
	"date":   formatDate,
	"fix":    FixLabel,
	"status": StatusLabel,
	"upper":  strings.ToUpper,
	"join":   join,
	"bytes":  formatBytes,
	"uptime": formatUptime,
	"runsOn": runsOn,
}).ParseFS(templates, "templates/report.html.tmpl"))

// HTML renders a report as one self-contained page; downloads are offered
// at its top when it is shown through a share link.
func HTML(report Report, fingerprint string, downloads ...Link) ([]byte, error) {
	v := newView(report, fingerprint)
	v.Downloads = downloads
	var buffer bytes.Buffer
	if err := page.Execute(&buffer, v); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
