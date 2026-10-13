package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"

	"deaconguard/internal/audit"
	"deaconguard/internal/checks"
)

// The PDF uses the built-in Helvetica, so the server needs no font files;
// text is converted to the Windows-1252 character set those fonts cover.

const (
	pageMargin = 18.0
	pageWidth  = 210.0 - 2*pageMargin
)

type rgb struct{ r, g, b int }

var (
	ink     = rgb{15, 23, 42}
	muted   = rgb{100, 116, 139}
	line    = rgb{226, 232, 240}
	soft    = rgb{248, 250, 252}
	accent  = rgb{79, 70, 229}
	red     = rgb{185, 28, 28}
	amber   = rgb{180, 83, 9}
	green   = rgb{4, 120, 87}
	gradeBG = map[string]rgb{"A": {5, 150, 105}, "B": {209, 250, 229}, "C": {254, 243, 199}, "D": {255, 237, 213}, "F": {220, 38, 38}}
	gradeFG = map[string]rgb{"A": {255, 255, 255}, "B": {6, 95, 70}, "C": {146, 64, 14}, "D": {154, 52, 18}, "F": {255, 255, 255}}
	sevFG   = map[string]rgb{"CRITICAL": red, "HIGH": {194, 65, 12}, "MEDIUM": amber, "LOW": muted, "UNKNOWN": muted}
	statFG  = map[string]rgb{"pass": green, "fail": red, "accepted": {55, 48, 163}, "na": muted, "unknown": amber}
)

type pdfWriter struct {
	pdf *fpdf.Fpdf
	tr  func(string) string
	r   Report
}

func (w *pdfWriter) color(c rgb)                     { w.pdf.SetTextColor(c.r, c.g, c.b) }
func (w *pdfWriter) fill(c rgb)                      { w.pdf.SetFillColor(c.r, c.g, c.b) }
func (w *pdfWriter) draw(c rgb)                      { w.pdf.SetDrawColor(c.r, c.g, c.b) }
func (w *pdfWriter) font(style string, size float64) { w.pdf.SetFont("Helvetica", style, size) }

// text writes a paragraph across the page width.
func (w *pdfWriter) text(value string, size float64, style string, c rgb) {
	w.font(style, size)
	w.color(c)
	w.pdf.MultiCell(0, size*0.45, w.tr(value), "", "L", false)
}

func (w *pdfWriter) heading(value string) {
	w.ensure(24)
	w.pdf.Ln(6)
	w.text(value, 14, "B", ink)
	w.draw(line)
	y := w.pdf.GetY() + 1
	w.pdf.Line(pageMargin, y, pageMargin+pageWidth, y)
	w.pdf.Ln(4)
}

func (w *pdfWriter) subheading(value string) {
	w.ensure(16)
	w.pdf.Ln(3)
	w.text(strings.ToUpper(value), 9, "B", muted)
	w.pdf.Ln(1)
}

// ensure starts a new page unless height millimetres fit.
func (w *pdfWriter) ensure(height float64) {
	_, pageHeight := w.pdf.GetPageSize()
	if w.pdf.GetY()+height > pageHeight-pageMargin-8 {
		w.pdf.AddPage()
	}
}

// row draws one table row whose cells wrap, on a new page if needed.
func (w *pdfWriter) row(widths []float64, cells []string, colors []rgb, header bool) {
	size := 8.5
	style := ""
	if header {
		size, style = 7.5, "B"
	}
	w.font(style, size)
	lineHeight := size * 0.42
	lines := 1
	for index, cell := range cells {
		if count := len(w.pdf.SplitLines([]byte(w.tr(cell)), widths[index]-2)); count > lines {
			lines = count
		}
	}
	height := float64(lines)*lineHeight + 2
	w.ensure(height)
	x, y := pageMargin, w.pdf.GetY()
	for index, cell := range cells {
		w.pdf.SetXY(x+1, y+1)
		c := ink
		if header {
			c = muted
		} else if colors != nil && colors[index] != (rgb{}) {
			c = colors[index]
		}
		w.color(c)
		value := cell
		if header {
			value = strings.ToUpper(cell)
		}
		w.pdf.MultiCell(widths[index]-2, lineHeight, w.tr(value), "", "L", false)
		x += widths[index]
	}
	w.draw(line)
	w.pdf.Line(pageMargin, y+height, pageMargin+pageWidth, y+height)
	w.pdf.SetXY(pageMargin, y+height)
}

// PDF renders a report for printing and handing over.
func PDF(report Report, fingerprint string) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(pageMargin, pageMargin, pageMargin)
	pdf.SetAutoPageBreak(false, pageMargin)
	pdf.AliasNbPages("{nb}")
	pdf.SetTitle(report.Title()+": "+report.Host, true)
	pdf.SetCreator(report.Generator, true)
	pdf.SetAuthor(strings.Trim(report.GeneratedBy+", "+report.Branding.Company, ", "), true)
	w := &pdfWriter{pdf: pdf, tr: pdf.UnicodeTranslatorFromDescriptor(""), r: report}

	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		w.font("", 7.5)
		w.color(muted)
		left := report.Branding.Company
		if left != "" {
			left += " · "
		}
		pdf.CellFormat(pageWidth/2, 4, w.tr(left+report.Title()+" · "+report.Host), "", 0, "L", false, 0, "")
		pdf.CellFormat(pageWidth/2, 4, w.tr(fmt.Sprintf("Report %s · page %d of {nb}", report.ID[:8], pdf.PageNo())), "", 0, "R", false, 0, "")
	})

	w.cover(fingerprint)
	pdf.AddPage()
	w.summary()
	w.comparison()
	w.controls()
	w.policies()
	w.compliance()
	w.vulnerabilities()
	w.findings()
	w.inventory()
	w.closing(fingerprint)

	if err := pdf.Error(); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := pdf.Output(&buffer); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (w *pdfWriter) cover(fingerprint string) {
	pdf, r := w.pdf, w.r
	pdf.AddPage()
	y := pageMargin
	if len(r.Branding.Logo) > 0 {
		imageType := map[string]string{"image/png": "PNG", "image/jpeg": "JPG"}[r.Branding.LogoType]
		if imageType != "" {
			info := pdf.RegisterImageOptionsReader("logo", fpdf.ImageOptions{ImageType: imageType}, bytes.NewReader(r.Branding.Logo))
			if info != nil && pdf.Error() == nil {
				height := 16.0
				width := info.Width() * height / info.Height()
				if width > 70 {
					width, height = 70, info.Height()*70/info.Width()
				}
				pdf.ImageOptions("logo", pageMargin, y, width, height, false, fpdf.ImageOptions{ImageType: imageType}, 0, "")
				y += height + 4
			} else {
				pdf.ClearError()
			}
		}
	}
	pdf.SetXY(pageMargin, y)
	if r.Branding.Company != "" {
		w.text(r.Branding.Company, 12, "B", ink)
	}
	if r.Branding.Contact != "" {
		w.text(r.Branding.Contact, 9, "", muted)
	}
	w.fill(accent)
	pdf.Rect(pageMargin, pdf.GetY()+4, pageWidth, 1.2, "F")
	pdf.SetY(pdf.GetY() + 18)
	w.text(r.Title(), 26, "B", ink)
	pdf.Ln(2)
	w.text(r.Host, 16, "", ink)
	if r.OS != "" {
		w.text(r.OS, 11, "", muted)
	}
	if support := r.Support(); support != "" {
		w.text("Release support: "+support, 9, "", muted)
	}
	pdf.Ln(10)

	facts := [][2]string{}
	if r.Client != "" {
		facts = append(facts, [2]string{"Prepared for", r.Client})
	}
	facts = append(facts, [2]string{"Prepared by", strings.Trim(r.GeneratedBy+", "+r.Branding.Company, ", ")},
		[2]string{"Scanned", formatDate(r.StartedAt)}, [2]string{"Report generated", formatDate(r.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"))})
	for _, fact := range facts {
		w.font("", 9)
		w.color(muted)
		pdf.CellFormat(42, 6, w.tr(fact[0]), "", 0, "L", false, 0, "")
		w.font("", 11)
		w.color(ink)
		pdf.MultiCell(0, 6, w.tr(fact[1]), "", "L", false)
	}

	if a := r.Audit; a != nil {
		pdf.Ln(12)
		top := pdf.GetY()
		w.fill(soft)
		w.draw(line)
		pdf.RoundedRect(pageMargin, top, pageWidth, 38, 3, "1234", "FD")
		background, foreground := gradeBG[a.Grade], gradeFG[a.Grade]
		w.fill(background)
		pdf.RoundedRect(pageMargin+6, top+6, 26, 26, 3, "1234", "F")
		pdf.SetXY(pageMargin+6, top+9)
		w.font("B", 34)
		w.color(foreground)
		pdf.CellFormat(26, 20, a.Grade, "", 0, "C", false, 0, "")
		pdf.SetXY(pageMargin+38, top+8)
		w.font("B", 14)
		w.color(ink)
		pdf.CellFormat(0, 7, w.tr(fmt.Sprintf("Score %d of 100", a.Score)), "", 2, "L", false, 0, "")
		w.font("", 10)
		w.color(muted)
		pdf.SetX(pageMargin + 38)
		pdf.MultiCell(pageWidth-44, 5, w.tr(fmt.Sprintf("%d of %d controls passed · %d failed · %d accepted as risks · %d not applicable",
			a.Counts.Passed, a.Counts.Passed+a.Counts.Failed, a.Counts.Failed, a.Counts.Accepted, a.Counts.NotApplicable)), "", "L", false)
		pdf.SetY(top + 42)
		for _, reason := range a.Caps {
			w.text("! "+reason, 9.5, "", red)
		}
		for _, reason := range a.Incomplete {
			w.text("Not fully checked: "+reason, 9.5, "", amber)
		}
	}

	_, pageHeight := pdf.GetPageSize()
	pdf.SetY(pageHeight - pageMargin - 26)
	w.text("Report "+r.ID, 8, "", muted)
	w.text("Fingerprint (SHA-256): "+FormatFingerprint(fingerprint), 8, "", muted)
	w.text("Check it on the DeaconGuard server's Verify a report page to confirm this report wasn't changed.", 8, "", muted)
}

func (w *pdfWriter) summary() {
	r := w.r
	w.heading("Summary")
	if r.Notes != "" {
		w.text(r.Notes, 10, "", ink)
		w.pdf.Ln(3)
	}
	if r.Audit != nil {
		w.text("The score weighs each baseline control by severity (critical 10, high 6, medium 3, low 1). The grade is A from 90, B from 80, "+
			"C from 70, D from 60, then lowered by anything that should stop a handover.", 9, "", muted)
		w.pdf.Ln(3)
	}
	widths := []float64{58, 90, 26}
	w.row(widths, []string{"Check", "Result", "Status"}, nil, true)
	if r.Packages != nil {
		w.row(widths, []string{"Package vulnerabilities", fmt.Sprintf("%d critical and %d high with a fix available; %d in all",
			r.Packages.Actionable.Critical, r.Packages.Actionable.High, len(r.Vulnerabilities)), ""}, nil, false)
		if e := r.Exploit; e != nil {
			w.row(widths, []string{"Exploitation", fmt.Sprintf("%d known to be exploited (CISA KEV), %d of them with a fix available; %d likely to be exploited (EPSS 10%% or more)",
				e.Known, e.KnownFixable, e.Likely), ""}, nil, false)
		}
	}
	for _, check := range r.CheckResults {
		w.row(widths, []string{check.Name, check.Summary, check.Status}, nil, false)
	}
	if r.Audit != nil {
		w.row(widths, []string{"Hardening baseline", fmt.Sprintf("%d of %d controls passed", r.Audit.Counts.Passed,
			r.Audit.Counts.Passed+r.Audit.Counts.Failed), ""}, nil, false)
	}
}

func (w *pdfWriter) comparison() {
	c := w.r.Comparison
	if c == nil {
		return
	}
	w.heading("Since the audit of " + formatDate(c.Date))
	w.text(fmt.Sprintf("Then: grade %s, score %d, %d critical and %d high vulnerabilities with a fix available.", c.Grade, c.Score, c.CriticalThen, c.HighThen), 10, "", ink)
	if len(c.Fixed) > 0 {
		w.subheading(fmt.Sprintf("Fixed since then (%d)", len(c.Fixed)))
		for _, item := range c.Fixed {
			w.text("- "+item, 9.5, "", green)
		}
	}
	if len(c.NewFailures) > 0 {
		w.subheading(fmt.Sprintf("Failing now, not then (%d)", len(c.NewFailures)))
		for _, item := range c.NewFailures {
			w.text("- "+item, 9.5, "", red)
		}
	}
	if len(c.Fixed)+len(c.NewFailures) == 0 {
		w.text("No control changed between the two audits.", 10, "", muted)
	}
}

func (w *pdfWriter) controls() {
	a := w.r.Audit
	if a == nil {
		return
	}
	w.heading("Hardening baseline")
	widths := []float64{82, 23, 23, 23, 23}
	w.row(widths, []string{"Category", "Passed", "Failed", "Accepted", "N/A"}, nil, true)
	for _, category := range a.Categories {
		if category.Passed+category.Failed+category.Accepted+category.NotApplicable+category.Unknown == 0 {
			continue
		}
		failColor := rgb{}
		if category.Failed > 0 {
			failColor = red
		}
		w.row(widths, []string{category.Name, fmt.Sprint(category.Passed), fmt.Sprint(category.Failed), fmt.Sprint(category.Accepted),
			fmt.Sprint(category.NotApplicable + category.Unknown)}, []rgb{{}, {}, failColor, {}, {}}, false)
	}
	groups := map[string][]audit.Control{}
	for _, control := range a.Controls {
		groups[control.Status] = append(groups[control.Status], control)
	}
	for _, group := range []struct{ status, title string }{{checks.ControlFail, "Failed controls"}, {audit.Accepted, "Accepted risks"}} {
		if len(groups[group.status]) == 0 {
			continue
		}
		w.subheading(fmt.Sprintf("%s (%d)", group.title, len(groups[group.status])))
		for _, control := range groups[group.status] {
			w.controlBlock(control)
		}
	}
	short := []float64{18, 70, 86}
	for _, group := range []struct {
		statuses []string
		title    string
	}{
		{[]string{checks.ControlPass}, "Passed controls"}, {[]string{checks.ControlNA, checks.ControlUnknown}, "Not applicable or not checked"},
	} {
		var listed []audit.Control
		for _, status := range group.statuses {
			listed = append(listed, groups[status]...)
		}
		if len(listed) == 0 {
			continue
		}
		w.subheading(fmt.Sprintf("%s (%d)", group.title, len(listed)))
		for _, control := range listed {
			w.row(short, []string{control.ID, control.Title, control.Evidence}, []rgb{muted, {}, muted}, false)
		}
	}
}

func (w *pdfWriter) controlBlock(control audit.Control) {
	pdf := w.pdf
	w.ensure(34)
	w.font("B", 10)
	w.color(ink)
	pdf.CellFormat(pageWidth-50, 5, w.tr(control.ID+"  "+control.Title), "", 0, "L", false, 0, "")
	w.font("B", 8)
	w.color(sevFG[strings.ToUpper(control.Severity)])
	pdf.CellFormat(25, 5, strings.ToUpper(control.Severity), "", 0, "R", false, 0, "")
	w.color(statFG[control.Status])
	pdf.CellFormat(25, 5, w.tr(StatusLabel(control.Status)), "", 1, "R", false, 0, "")
	for _, part := range [][2]string{{"Found: ", control.Evidence}, {"Why it matters: ", control.Rationale}, {"How to fix: ", control.Remediation}} {
		w.font("B", 8.5)
		w.color(ink)
		pdf.Write(4, w.tr(part[0]))
		w.font("", 8.5)
		w.color(rgb{51, 65, 85})
		pdf.Write(4, w.tr(part[1]))
		pdf.Ln(4.5)
	}
	if exception := control.Exception; exception != nil {
		scope := "for every host"
		if exception.HostID != "" {
			scope = "for this host"
		}
		until := ""
		if exception.ExpiresAt != "" {
			until = ", until " + formatDate(exception.ExpiresAt)
		}
		w.text(fmt.Sprintf("Accepted %s by %s%s: %s", scope, exception.CreatedBy, until, exception.Reason), 8.5, "I", rgb{55, 48, 163})
	}
	w.draw(line)
	pdf.Line(pageMargin, pdf.GetY()+1.5, pageMargin+pageWidth, pdf.GetY()+1.5)
	pdf.SetY(pdf.GetY() + 3)
}

func (w *pdfWriter) vulnerabilities() {
	r := w.r
	if r.Packages == nil {
		return
	}
	w.heading("Vulnerabilities")
	if len(r.Vulnerabilities) == 0 {
		w.text("No vulnerable packages were found.", 10, "", ink)
		return
	}
	v := newView(r, "")
	source := "From the distribution's own security advisories."
	if e := r.Exploit; e != nil {
		source += " Exploitation from CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS; known exploited ones come first."
	}
	w.text(source, 9, "", muted)
	w.subheading(fmt.Sprintf("Fixed by an update or a restart (%d)", len(v.Vulnerabilities)))
	if len(v.Vulnerabilities) == 0 {
		w.text("Nothing an update or a restart would fix.", 10, "", ink)
	} else {
		// What clears it goes with the fixed version: an update, unless a
		// restart is all that is left.
		widths := []float64{31, 28, 27, 30, 18, 12, 28}
		w.row(widths, []string{"CVE", "Package", "Installed", "Fixed in", "Severity", "CVSS", "Exploitation"}, nil, true)
		for _, vulnerability := range v.Vulnerabilities {
			fixed := vulnerability.Fixed
			if vulnerability.Fix == "reboot" {
				fixed += " (restart)"
			}
			exploitColor := rgb{}
			if vulnerability.KEV {
				exploitColor = sevFG["CRITICAL"]
			}
			w.row(widths, []string{vulnerability.ID, vulnerability.Package, vulnerability.Installed, fixed, vulnerability.Severity,
				vulnerability.CVSS(), vulnerability.Exploitation()},
				[]rgb{{}, {}, {}, {}, sevFG[vulnerability.Severity], {}, exploitColor}, false)
		}
	}
	if len(v.Waiting) > 0 {
		w.subheading(fmt.Sprintf("Waiting on the distribution, by package (%d packages)", len(v.Waiting)))
		w.text("Updating can't fix these yet. The CSV, Excel and JSON versions list every CVE.", 9, "", muted)
		w.pdf.Ln(1)
		widths := []float64{46, 42, 14, 20, 22, 30}
		w.row(widths, []string{"Package", "Installed", "CVEs", "Exploited", "Highest", "What clears it"}, nil, true)
		for _, group := range v.Waiting {
			exploited, exploitColor := "", rgb{}
			if group.Exploited > 0 {
				exploited, exploitColor = fmt.Sprint(group.Exploited), sevFG["CRITICAL"]
			}
			w.row(widths, []string{group.Package, group.Installed, fmt.Sprint(group.Count), exploited, group.Severity, FixLabel(group.Fix)},
				[]rgb{{}, {}, {}, exploitColor, sevFG[group.Severity], {}}, false)
		}
	}
}

func (w *pdfWriter) findings() {
	for _, check := range w.r.CheckResults {
		if len(check.Findings) == 0 {
			continue
		}
		w.heading(check.Name)
		widths := []float64{20, 80, 74}
		w.row(widths, []string{"Severity", "Finding", "Evidence"}, nil, true)
		for _, finding := range check.Findings {
			w.row(widths, []string{finding.Severity, finding.Title + ". " + finding.Detail, finding.Evidence},
				[]rgb{sevFG[finding.Severity], {}, muted}, false)
		}
	}
}

func (w *pdfWriter) inventory() {
	inventory := w.r.Inventory
	if inventory == nil {
		return
	}
	w.heading("Inventory")
	widths := []float64{52, 122}
	for _, fact := range [][2]string{
		{"Host name", inventory.Hostname}, {"Operating system", inventory.OS}, {"Kernel", inventory.Kernel + " (" + inventory.Architecture + ")"},
		{"Runs on", runsOn(inventory.Virtualization)}, {"Processors", fmt.Sprint(inventory.CPUs)}, {"Memory", formatBytes(inventory.MemoryBytes)},
		{"Up for", formatUptime(inventory.UptimeSeconds)}, {"Packages", fmt.Sprint(inventory.Packages)},
		{"Time zone", timezone(inventory.Timezone, inventory.TimeSynced)},
		{"Administrators", join(inventory.Administrators)}, {"Accounts that can log in", join(inventory.LoginUsers)}, {"Addresses", join(inventory.Addresses)},
	} {
		w.row(widths, []string{fact[0], fact[1]}, []rgb{muted, {}}, false)
	}
	if len(inventory.Disks) > 0 {
		w.subheading("Disks")
		disks := []float64{90, 42, 42}
		w.row(disks, []string{"Mount", "Size", "Used"}, nil, true)
		for _, disk := range inventory.Disks {
			w.row(disks, []string{disk.Mount, formatBytes(disk.SizeBytes), fmt.Sprintf("%d%%", disk.UsedPercent)}, nil, false)
		}
	}
	if len(inventory.Listening) > 0 {
		w.subheading("Listening services")
		ports := []float64{40, 40, 94}
		w.row(ports, []string{"Protocol", "Port", "Listens on"}, nil, true)
		for _, socket := range inventory.Listening {
			where, c := socket.Address, rgb{}
			if socket.Exposed {
				where, c = "all interfaces", amber
			}
			w.row(ports, []string{strings.ToUpper(socket.Protocol), fmt.Sprint(socket.Port), where}, []rgb{{}, {}, c}, false)
		}
	}
}

func (w *pdfWriter) closing(fingerprint string) {
	w.ensure(30)
	w.pdf.Ln(8)
	w.text(fmt.Sprintf("Report %s, generated %s by %s.", w.r.ID, formatDate(w.r.GeneratedAt.Format("2006-01-02T15:04:05Z07:00")), w.r.Generator), 8, "", muted)
	w.text("Fingerprint (SHA-256): "+FormatFingerprint(fingerprint), 8, "", muted)
	w.text("Like every DeaconGuard scan, this only read the machine: it changed nothing. A clean result means nothing was found in what was "+
		"checked, not that the machine is guaranteed secure.", 8, "", muted)
}

func timezone(zone string, synced bool) string {
	if zone == "" {
		zone = "—"
	}
	if synced {
		zone += ", clock synchronised"
	}
	return zone
}

var reqFG = map[string]rgb{"met": green, "met_accepted": {55, 48, 163}, "not_met": red, "not_checked": amber, "not_evaluated": muted}

func (w *pdfWriter) policies() {
	for _, result := range w.r.Policies {
		w.heading("Policy: " + result.Name)
		w.text(fmt.Sprintf("Your organisation's own controls, tested on the same settings; they don't change the grade. %d passed · %d failed · %d accepted · %d not applicable or not checked.",
			result.Counts.Passed, result.Counts.Failed, result.Counts.Accepted, result.Counts.NotApplicable+result.Counts.Unknown), 9, "", muted)
		w.pdf.Ln(2)
		for _, control := range result.Controls {
			if control.Status == checks.ControlFail || control.Status == audit.Accepted {
				w.controlBlock(control)
			}
		}
		widths := []float64{22, 64, 24, 64}
		for _, control := range result.Controls {
			if control.Status != checks.ControlFail && control.Status != audit.Accepted {
				w.row(widths, []string{control.ID, control.Title, StatusLabel(control.Status), control.Evidence}, []rgb{muted, {}, statFG[control.Status], muted}, false)
			}
		}
	}
}

func (w *pdfWriter) compliance() {
	for _, result := range w.r.Compliance {
		w.heading(result.Framework.Name)
		other := ""
		if result.Other > 0 {
			other = fmt.Sprintf(", %d not checked", result.Other)
		}
		w.text(fmt.Sprintf("The requirements this audit gives evidence for: %d met, %d not met%s. This is DeaconGuard's mapping, for guidance. "+
			"The framework also has requirements about policies, people and processes that no scan can check, so this is not a certification.",
			result.Met, result.NotMet, other), 9, "", muted)
		w.pdf.Ln(2)
		widths := []float64{70, 30, 74}
		w.row(widths, []string{"Requirement", "Status", "Evidence"}, nil, true)
		for _, requirement := range result.Requirements {
			var evidence []string
			for _, control := range requirement.Controls {
				evidence = append(evidence, control.ID+" "+StatusLabel(control.Status))
			}
			w.row(widths, []string{requirement.ID + "  " + requirement.Name, RequirementLabel(requirement.Status), strings.Join(evidence, ", ")},
				[]rgb{{}, reqFG[requirement.Status], muted}, false)
		}
	}
}
