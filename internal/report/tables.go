package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"
)

// rows lists every item of a report, one per row: controls, vulnerabilities
// and other findings, for CSV and the Excel workbook's Items sheet.
func rows(report Report) [][]string {
	table := [][]string{{"Type", "ID", "Title", "Severity", "Status", "Details", "How to fix", "CVSS", "EPSS", "Known exploited"}}
	if report.Audit != nil {
		for _, control := range report.Audit.Controls {
			details := control.Evidence
			if control.Exception != nil {
				details += " | accepted by " + control.Exception.CreatedBy + ": " + control.Exception.Reason
			}
			table = append(table, []string{"Control", control.ID, control.Title, strings.ToUpper(control.Severity),
				StatusLabel(control.Status), details, control.Remediation})
		}
	}
	for _, result := range report.Policies {
		for _, control := range result.Controls {
			table = append(table, []string{"Policy: " + result.Name, control.ID, control.Title, strings.ToUpper(control.Severity),
				StatusLabel(control.Status), control.Evidence, control.Remediation})
		}
	}
	for _, result := range report.Compliance {
		for _, requirement := range result.Requirements {
			var evidence []string
			for _, control := range requirement.Controls {
				evidence = append(evidence, control.ID+" "+StatusLabel(control.Status))
			}
			table = append(table, []string{result.Framework.Short + " requirement", requirement.ID, requirement.Name, "",
				RequirementLabel(requirement.Status), strings.Join(evidence, ", "), ""})
		}
	}
	for _, vulnerability := range report.Vulnerabilities {
		epss, known := "", ""
		if vulnerability.EPSS != nil {
			epss = fmt.Sprintf("%.4f", *vulnerability.EPSS)
		}
		if vulnerability.KEV {
			known = "yes, due " + vulnerability.KEVDue
			if vulnerability.Ransomware {
				known += ", used in ransomware"
			}
		}
		table = append(table, []string{"Vulnerability", vulnerability.ID, vulnerability.Package + " " + vulnerability.Installed,
			vulnerability.Severity, FixLabel(vulnerability.Fix), vulnerability.Title, fixedIn(vulnerability), vulnerability.CVSS(), epss, known})
	}
	for _, check := range report.CheckResults {
		for _, finding := range check.Findings {
			table = append(table, []string{check.Name, finding.Rule, finding.Title, finding.Severity, "Found", finding.Evidence, finding.Detail})
		}
	}
	// Every row has the header's columns, for spreadsheet tools.
	for index := range table {
		for len(table[index]) < len(table[0]) {
			table[index] = append(table[index], "")
		}
	}
	return table
}

func fixedIn(vulnerability Vulnerability) string {
	if vulnerability.Fixed == "" {
		return ""
	}
	return "Update " + vulnerability.Package + " to " + vulnerability.Fixed
}

// safeCell keeps a spreadsheet from running a cell as a formula, since
// evidence comes from the scanned machine.
func safeCell(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// CSV renders every item of a report as one CSV table.
func CSV(report Report) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	for _, row := range rows(report) {
		safe := make([]string, len(row))
		for index, cell := range row {
			safe[index] = safeCell(cell)
		}
		if err := writer.Write(safe); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

// JSON renders the report's snapshot, indented, with its fingerprint.
func JSON(report Report, fingerprint string) ([]byte, error) {
	return json.MarshalIndent(struct {
		Fingerprint string `json:"fingerprint_sha256"`
		Report      Report `json:"report"`
	}{fingerprint, report}, "", "  ")
}

// XLSX renders a workbook: Summary, Items, Vulnerabilities and Inventory.
func XLSX(report Report, fingerprint string) ([]byte, error) {
	book := excelize.NewFile()
	defer book.Close()
	bold, err := book.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true}})
	if err != nil {
		return nil, err
	}
	write := func(sheet string, table [][]string, widths ...float64) error {
		for rowIndex, row := range table {
			for columnIndex, value := range row {
				cell, _ := excelize.CoordinatesToCellName(columnIndex+1, rowIndex+1)
				if err := book.SetCellStr(sheet, cell, safeCell(value)); err != nil {
					return err
				}
			}
		}
		for index, width := range widths {
			column, _ := excelize.ColumnNumberToName(index + 1)
			if err := book.SetColWidth(sheet, column, column, width); err != nil {
				return err
			}
		}
		return nil
	}

	summary := [][]string{
		{report.Title()},
		{"Host", report.Host},
		{"Operating system", report.OS},
		{"Release support", report.Support()},
		{"Prepared for", report.Client},
		{"Prepared by", strings.Trim(report.GeneratedBy+", "+report.Branding.Company, ", ")},
		{"Scanned", formatDate(report.StartedAt)},
		{"Report ID", report.ID},
		{"Fingerprint (SHA-256)", fingerprint},
	}
	if report.Audit != nil {
		summary = append(summary, []string{"Grade", report.Audit.Grade}, []string{"Score", fmt.Sprint(report.Audit.Score)},
			[]string{"Controls passed", fmt.Sprint(report.Audit.Counts.Passed)}, []string{"Controls failed", fmt.Sprint(report.Audit.Counts.Failed)},
			[]string{"Risks accepted", fmt.Sprint(report.Audit.Counts.Accepted)})
		for _, reason := range report.Audit.Caps {
			summary = append(summary, []string{"Holds the grade back", reason})
		}
		for _, reason := range report.Audit.Incomplete {
			summary = append(summary, []string{"Not fully checked", reason})
		}
	}
	if report.Packages != nil {
		summary = append(summary, []string{"Critical vulnerabilities with a fix", fmt.Sprint(report.Packages.Actionable.Critical)},
			[]string{"High vulnerabilities with a fix", fmt.Sprint(report.Packages.Actionable.High)},
			[]string{"Vulnerabilities in all", fmt.Sprint(len(report.Vulnerabilities))})
		if e := report.Exploit; e != nil {
			summary = append(summary, []string{"Known exploited (CISA KEV)", fmt.Sprint(e.Known)},
				[]string{"Known exploited with a fix available", fmt.Sprint(e.KnownFixable)},
				[]string{"Likely exploited (EPSS 10% or more)", fmt.Sprint(e.Likely)})
		}
	}
	for _, check := range report.CheckResults {
		summary = append(summary, []string{check.Name, check.Summary + " (" + check.Status + ")"})
	}
	if report.Notes != "" {
		summary = append(summary, []string{"Notes", report.Notes})
	}
	if err := book.SetSheetName("Sheet1", "Summary"); err != nil {
		return nil, err
	}
	if err := write("Summary", summary, 36, 90); err != nil {
		return nil, err
	}
	book.SetCellStyle("Summary", "A1", "A1", bold)

	if _, err := book.NewSheet("Items"); err != nil {
		return nil, err
	}
	if err := write("Items", rows(report), 16, 22, 50, 12, 16, 70, 60); err != nil {
		return nil, err
	}
	book.SetCellStyle("Items", "A1", "G1", bold)
	book.SetPanes("Items", &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"})
	if last := len(rows(report)); last > 1 {
		book.AutoFilter("Items", fmt.Sprintf("A1:G%d", last), nil)
	}

	if report.Inventory != nil {
		inventory := report.Inventory
		table := [][]string{
			{"Host name", inventory.Hostname}, {"Operating system", inventory.OS}, {"Kernel", inventory.Kernel + " (" + inventory.Architecture + ")"},
			{"Runs on", runsOn(inventory.Virtualization)}, {"Processors", fmt.Sprint(inventory.CPUs)}, {"Memory", formatBytes(inventory.MemoryBytes)},
			{"Up for", formatUptime(inventory.UptimeSeconds)}, {"Packages", fmt.Sprint(inventory.Packages)}, {"Time zone", inventory.Timezone},
			{"Administrators", join(inventory.Administrators)}, {"Accounts that can log in", join(inventory.LoginUsers)}, {"Addresses", join(inventory.Addresses)},
		}
		for _, disk := range inventory.Disks {
			table = append(table, []string{"Disk " + disk.Mount, fmt.Sprintf("%s, %d%% used", formatBytes(disk.SizeBytes), disk.UsedPercent)})
		}
		for _, socket := range inventory.Listening {
			where := socket.Address
			if socket.Exposed {
				where = "all interfaces"
			}
			table = append(table, []string{fmt.Sprintf("Listening %s %d", strings.ToUpper(socket.Protocol), socket.Port), where})
		}
		if _, err := book.NewSheet("Inventory"); err != nil {
			return nil, err
		}
		if err := write("Inventory", table, 30, 80); err != nil {
			return nil, err
		}
	}
	book.SetActiveSheet(0)
	var buffer bytes.Buffer
	if err := book.Write(&buffer); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
