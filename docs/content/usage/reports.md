---
title: Reports
description: Turn an audit or scan into a branded PDF, HTML, Excel, CSV or JSON report, share it with a link, and check that a report is genuine.
---

A **report** turns a [server audit](./audits.md) or a scan into something you can hand over: a PDF with your company's name and logo and your client's name, and the same content as HTML, Excel, CSV or JSON.

## Create a report

On an audit's page, or a scan's report page, choose **Create report** (as an operator or admin) and fill in:

- **Prepared for**: the client or team receiving it. Optional.
- **Notes**: shown on the summary page, for example what was handed over. Optional.
- **Compare with** (audits only): the audit before this one, a chosen earlier audit, or nothing. The report then lists the controls fixed since then, any that started failing, and the earlier grade and score.
- **Include a compliance mapping for** (audits only): any of NIST SP 800-53, PCI DSS, HIPAA and ISO/IEC 27001. Each gets a section with its requirements, their status and their evidence. See [Compliance](./compliance.md).

Reports of audits also include your enabled [policies](./policies.md). Reports of scans from 0.19.0 say whether the machine's release still got security fixes, under **Release support** (see [Release lifecycle](../supported-distributions.md#release-lifecycle)).

A report is **frozen** when it's made: accepting a risk or running another audit later doesn't change it. Create a new report for the new state.

## Download it

Every report can be downloaded, by anyone signed in, as:

| Format | Best for |
| --- | --- |
| **PDF** | Handing over. A cover page with your logo, company, the client, the grade and score; a summary; changes since the earlier audit; every failed control with what was found, why it matters and how to fix it; accepted risks; passed controls; vulnerabilities with their CVSS score and exploitation, known exploited first; the other checks' findings; the inventory. |
| **HTML** | A single page that opens in any browser and prints well. Same content as the PDF. |
| **Excel** | Working through the findings: a Summary sheet, an Items sheet with every control, vulnerability and finding (with filters), and the Inventory. |
| **CSV** | Importing into other tools: one row per control, vulnerability and finding. |
| **JSON** | Automation: the complete report, with its fingerprint. |

The PDF and HTML list the vulnerabilities an update or a restart fixes one by one, and those waiting on the distribution by package, so the report stays readable. Excel, CSV and JSON list every CVE; CSV and Excel have **CVSS**, **EPSS** and **Known exploited** columns. See [what to fix first](./vulnerabilities.md). Spreadsheet cells that would start a formula are prefixed so they're shown as text.

The PDF is made by the DeaconGuard server itself, so nothing extra needs to be installed. It uses standard fonts, so characters outside Western European alphabets may show as `?`.

## Your company's branding

Admins set it once, under **Settings → Reports**:

- **Company name** and a **contact line**, such as an email address and phone number, shown on the cover and in the footer of every report;
- a **logo**: a PNG or JPEG of at most 256 KB, shown on the cover.

Reports made earlier keep the branding they were made with.

## Share a link

For a client without an account, an operator or admin can choose **Share** on a report:

- the link opens the report without signing in, with buttons to download it as PDF, Excel, CSV or JSON;
- it works for 1 to 30 days (7 by default), and can be **revoked** at any time from the report's row;
- the link is shown only once; DeaconGuard stores only a hash of it;
- every view and download through it is recorded in the audit log, and the report's row counts the views.

The client must be able to reach the server's dashboard address. If the dashboard is only reachable over your VPN, as [we recommend](../security/securing-the-dashboard.md), send the PDF instead.

## Verify a report

Every report shows its **ID** and **fingerprint** (a SHA-256 of its content) on its first and last page. To check that a report really came from your server and wasn't changed, open **Verify a report** (linked from **Server audits**), and enter both. DeaconGuard says whether it's genuine, and which host, client and grade it covers.

## Keeping reports

Reports are kept until someone deletes them, even if the scan they came from is deleted. They are stored in `deaconguard.db`, so [backups](./backup-and-restore.md) include them.
