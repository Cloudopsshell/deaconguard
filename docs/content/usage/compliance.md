---
title: Compliance
description: Read a server audit framework by framework, for NIST SP 800-53, PCI DSS, HIPAA, ISO/IEC 27001 and the DISA STIG for the machine's operating system, and include the mapping in reports.
---

Every [server audit](./audits.md) can be read framework by framework. DeaconGuard maps each control of its baseline, and its checks for vulnerabilities, file integrity and malware, to requirements of:

- **NIST SP 800-53 Rev. 5**
- **PCI DSS v4.0**
- **The HIPAA Security Rule** (45 CFR Part 164, Subpart C)
- **ISO/IEC 27001:2022 Annex A**
- **The DISA STIG for the machine's operating system** (1.24.0 and later), for Ubuntu 22.04 and 24.04 and for RHEL 8 and 9; see [DISA STIG](#disa-stig).

## What it means, and what it doesn't

The mapping says which of a framework's requirements a host audit gives **evidence** for. For each one, the audit shows:

| Status | Meaning |
| --- | --- |
| **Met** | Every control behind the requirement passed. |
| **Met, risk accepted** | They passed, or failed with an [accepted risk](./audits.md#accepted-risks). |
| **Not met** | At least one control behind it failed. |
| **Not checked** | A control behind it couldn't be checked, usually because the audit ran without root. |
| **Partly checked** | DISA STIG only: the control behind the rule passed, but the rule asks for more than the control checks. Check the rest by hand. |

This is DeaconGuard's own mapping, for guidance. Frameworks also require policies, training, physical security, vendor management and processes that no scan of a server can see. A server meeting every mapped requirement is not certified or compliant on that basis alone: an assessor decides that. Requirements are referred to by their number; the short names are DeaconGuard's own descriptions, not the standards' text.

## Where to see it

- **On an audit's page**, the **Compliance** card has a tab for each framework, with how many requirements are met and not met, and the controls behind each.
- **In reports**: when you create a report, choose the frameworks to include. Each gets a section listing its requirements, their status and their evidence, in the PDF, HTML, Excel and CSV.

## DISA STIG

From 1.24.0, each control of the Linux baseline names the rules of the DISA STIG for the machine's operating system that it checks:

| Machine | STIG |
| --- | --- |
| Ubuntu 22.04 | Canonical Ubuntu 22.04 LTS STIG, V2R10 (30 September 2026) |
| Ubuntu 24.04 | Canonical Ubuntu 24.04 LTS STIG, V1R7 (30 September 2026) |
| RHEL 8, Rocky Linux 8, AlmaLinux 8 | Red Hat Enterprise Linux 8 STIG, V2R9 (30 September 2026) |
| RHEL 9, Rocky Linux 9, AlmaLinux 9 | Red Hat Enterprise Linux 9 STIG, V2R10 (30 September 2026) |

Rocky Linux and AlmaLinux are rebuilds of RHEL, so their rules are the RHEL STIG's. Other systems, such as Debian, Ubuntu 20.04, Oracle Linux, SUSE and Alpine, get no STIG rules.

- **On an audit's page,** each control shows its rule IDs, such as `V-257985`. Its details name the STIG and say what the rule asks for beyond the control.
- **The Compliance card's DISA STIG tab** lists the STIG's rules that a control checks, with each rule's title as DISA publishes it.
- **In reports:** each control's rules are in the PDF and HTML and in the CSV and Excel **DISA STIG** column. Choose **DISA STIG** among the frameworks for a section listing each rule.

**A control is mapped only where it checks the same setting as the rule.** Many STIG rules ask for more than DeaconGuard's control, such as passwords of 15 characters where the control asks for 12. Then the control passing doesn't pass the rule: the audit marks the rule **Partly checked** and says what the STIG asks for. A failed control fails the rule too.

**This is not a STIG assessment.** A STIG has 190 to 450 rules; DeaconGuard's baseline checks a few dozen of them. Most rules need settings DeaconGuard doesn't read, such as audit rules for each command, the STIG's banner text, FIPS mode and documentation. The mapping, and the notes on what each rule asks for, are DeaconGuard's own. DISA publishes the STIGs openly; rule titles are quoted as DISA publishes them.

Scans from before 1.24.0 show the rules too: they're added when the audit is read, from the operating system the scan recorded. No agent upgrade is needed.

## The mapping

### NIST SP 800-53 Rev. 5

| Requirement | | Evidence from |
| --- | --- | --- |
| AC-2 | Account management | ACC-07, ACC-08, MACOS-10 |
| AC-2(3) | Disable accounts | ACC-09 |
| AC-3 | Access enforcement | ACC-06, FS-01, FS-02, FS-03, FS-04, FS-05, FS-08, FS-09, FS-10, FS-12, FS-13, KRN-06, SSH-12 |
| AC-3(3) | Mandatory access control | MAC-01 |
| AC-4 | Information flow enforcement | NET-01 |
| AC-6 | Least privilege | ACC-01, FS-11, SSH-01 |
| AC-7 | Unsuccessful logon attempts | ACC-05, ACC-11, SSH-05 |
| AC-8 | System use notification | SSH-13 |
| AC-12 | Session termination | SSH-06 |
| AC-17 | Remote access | MACOS-07, MACOS-08, SSH-01, SSH-02, SSH-09 |
| AU-2 | Event logging | LOG-01, LOG-02, NET-08, SSH-14 |
| AU-8 | Time stamps | MACOS-18, TIME-01, TIME-02 |
| AU-9 | Protection of audit information | LOG-04, LOG-05 |
| AU-11 | Audit record retention | LOG-04 |
| AU-12 | Audit record generation | LOG-01, LOG-02, LOG-03, SSH-14 |
| CM-6 | Configuration settings | ACC-06, ACC-07, FS-01, FS-03, FS-05, FS-06, FS-07, FS-08, FS-09, FS-10, FS-11, FS-12, KRN-02, KRN-03, KRN-05, KRN-06, KRN-07, MACOS-02, NET-02, NET-03, NET-04, NET-05, NET-07, NET-09, SSH-10, SSH-12 |
| CM-7 | Least functionality | FS-06, FS-07, MACOS-07, MACOS-08, MACOS-09, SSH-04, SVC-02, SVC-03, SVC-04, SVC-05, SVC-06 |
| CM-14 | Signed components | MACOS-03, UPD-03 |
| IA-2 | Identification and authentication | ACC-01, ACC-08, MACOS-10, MACOS-11, SSH-02, SSH-07, SSH-08 |
| IA-5 | Authenticator management | ACC-02, FS-02, FS-04, SSH-03 |
| IA-5(1) | Password-based authentication | ACC-03, ACC-04, ACC-10 |
| MP-7 | Media use | SVC-07 |
| RA-5 | Vulnerability monitoring and scanning | packages |
| SC-5 | Denial-of-service protection | NET-06, NET-07, SSH-09 |
| SC-7 | Boundary protection | MACOS-05, MACOS-06, NET-01, NET-02, NET-03, NET-04, NET-05, NET-08, NET-09, SVC-01, SVC-02, SVC-06 |
| SC-8 | Transmission confidentiality and integrity | SSH-11, SVC-03 |
| SC-10 | Network disconnect | SSH-06 |
| SC-13 | Cryptographic protection | SSH-11 |
| SC-28 | Protection of information at rest | MACOS-01 |
| SC-39 | Process isolation | KRN-04, MAC-01 |
| SI-2 | Flaw remediation | MACOS-12, MACOS-13, MACOS-14, MACOS-15, MACOS-16, MACOS-17, UPD-01, UPD-02, packages |
| SI-3 | Malicious code protection | MACOS-03, MACOS-04, MACOS-14, antivirus, malware, yara |
| SI-4 | System monitoring | malware |
| SI-7 | Software, firmware and information integrity | MACOS-02, UPD-03, integrity |
| SI-16 | Memory protection | KRN-01, KRN-03 |

### PCI DSS v4.0

| Requirement | | Evidence from |
| --- | --- | --- |
| 1.3.1 | Inbound traffic to the cardholder data environment is restricted | MACOS-05, MACOS-06, SVC-01, SVC-02 |
| 1.3.2 | Outbound traffic from the cardholder data environment is restricted | SVC-01 |
| 2.2.2 | Vendor default accounts are managed | ACC-07 |
| 2.2.4 | Only necessary services and functions are enabled | MACOS-07, MACOS-08, MACOS-09, SSH-04, SVC-02, SVC-03, SVC-04, SVC-05, SVC-06 |
| 2.2.5 | Insecure services are justified and secured | SVC-03 |
| 2.2.6 | System security parameters prevent misuse | ACC-06, FS-01, FS-02, FS-03, FS-04, FS-05, FS-06, FS-07, FS-08, FS-09, FS-10, FS-11, FS-12, KRN-01, KRN-02, KRN-03, KRN-04, KRN-05, KRN-06, KRN-07, MAC-01, MACOS-02, NET-01, NET-02, NET-03, NET-04, NET-05, NET-06, NET-07, NET-08, NET-09, SSH-09, SSH-10, SSH-12 |
| 2.2.7 | Administrative access is encrypted | SSH-01, SSH-11, SVC-03 |
| 5.2.1 | Anti-malware is deployed | MACOS-03, MACOS-04, MACOS-14, antivirus, malware, yara |
| 5.3.2 | Anti-malware scans run | antivirus, yara |
| 6.3.3 | Security patches are installed | MACOS-12, MACOS-13, MACOS-14, MACOS-15, MACOS-16, MACOS-17, UPD-01, UPD-02, packages |
| 8.2.1 | Every user has a unique ID | ACC-01, ACC-08 |
| 8.2.2 | Shared and generic accounts are controlled | MACOS-10, SSH-01 |
| 8.2.6 | Inactive accounts are removed or disabled | ACC-09 |
| 8.2.8 | Idle sessions require signing in again | SSH-06 |
| 8.3.1 | Users are authenticated | ACC-02, MACOS-11, SSH-02, SSH-03, SSH-07, SSH-08 |
| 8.3.2 | Authentication factors are unreadable when stored | FS-02, FS-04 |
| 8.3.4 | Failed logins lock the account | ACC-05, ACC-11, SSH-05 |
| 8.3.6 | Passwords have at least 12 characters | ACC-04 |
| 8.3.7 | Recent passwords can't be reused | ACC-10 |
| 8.3.9 | Passwords change at least every 90 days | ACC-03 |
| 10.2.1 | Audit logs are enabled | LOG-01, LOG-02, LOG-03, SSH-14 |
| 10.3.1 | Read access to audit logs is limited | LOG-05 |
| 10.5.1 | Audit logs are retained | LOG-04 |
| 10.6.1 | Clocks are synchronized | MACOS-18, TIME-01, TIME-02 |
| 11.3.1 | Internal vulnerability scans run | packages |
| 11.5.2 | Changes to critical files are detected | integrity |

### HIPAA Security Rule (45 CFR 164 Subpart C)

| Requirement | | Evidence from |
| --- | --- | --- |
| 164.308(a)(1)(ii)(A) | Risk analysis | packages |
| 164.308(a)(5)(ii)(B) | Protection from malicious software | MACOS-03, MACOS-04, MACOS-14, antivirus, malware, yara |
| 164.308(a)(5)(ii)(C) | Log-in monitoring | ACC-05, ACC-11, SSH-05 |
| 164.308(a)(5)(ii)(D) | Password management | ACC-03, ACC-04, ACC-10 |
| 164.310(d)(1) | Device and media controls | SVC-07 |
| 164.312(a)(1) | Access control | ACC-06, ACC-07, FS-01, FS-02, FS-03, FS-04, FS-13, MAC-01, MACOS-07, MACOS-08, SSH-01, SSH-04, SSH-10, SSH-12, SVC-02 |
| 164.312(a)(2)(i) | Unique user identification | ACC-01, ACC-08, MACOS-10 |
| 164.312(a)(2)(iii) | Automatic logoff | SSH-06 |
| 164.312(a)(2)(iv) | Encryption and decryption | MACOS-01 |
| 164.312(b) | Audit controls | LOG-01, LOG-02, LOG-03, LOG-04, LOG-05, MACOS-18, SSH-14, TIME-01, TIME-02 |
| 164.312(c)(1) | Integrity | FS-01, FS-05, FS-08, FS-09, FS-11, MACOS-02, UPD-03, integrity |
| 164.312(d) | Person or entity authentication | ACC-02, MACOS-11, SSH-02, SSH-03, SSH-07, SSH-08 |
| 164.312(e)(1) | Transmission security | MACOS-05, SSH-11, SVC-01, SVC-03 |

### ISO/IEC 27001:2022 Annex A

| Requirement | | Evidence from |
| --- | --- | --- |
| 5.16 | Identity management | ACC-08, MACOS-10 |
| 5.17 | Authentication information | ACC-02, ACC-03, ACC-04, ACC-10, FS-02, FS-04 |
| 5.18 | Access rights | ACC-07, ACC-09 |
| 7.10 | Storage media | SVC-07 |
| 8.2 | Privileged access rights | ACC-01, SSH-01 |
| 8.3 | Information access restriction | FS-13, MACOS-09 |
| 8.5 | Secure authentication | ACC-05, ACC-11, MACOS-11, SSH-02, SSH-03, SSH-05, SSH-06, SSH-07, SSH-08 |
| 8.7 | Protection against malware | MACOS-03, MACOS-04, MACOS-14, antivirus, malware, yara |
| 8.8 | Management of technical vulnerabilities | MACOS-12, MACOS-13, MACOS-14, MACOS-15, MACOS-16, MACOS-17, UPD-01, UPD-02, packages |
| 8.9 | Configuration management | ACC-06, FS-01, FS-02, FS-03, FS-04, FS-05, FS-06, FS-07, FS-08, FS-09, FS-10, FS-11, FS-12, KRN-01, KRN-02, KRN-03, KRN-04, KRN-05, KRN-06, KRN-07, MAC-01, MACOS-02, SSH-04, SSH-09, SSH-10, SSH-12, SVC-03, SVC-04, SVC-05 |
| 8.15 | Logging | LOG-01, LOG-02, LOG-03, LOG-04, LOG-05, SSH-14 |
| 8.16 | Monitoring activities | integrity, malware |
| 8.17 | Clock synchronization | MACOS-18, TIME-01, TIME-02 |
| 8.19 | Installation of software on operational systems | MACOS-03, UPD-03 |
| 8.20 | Networks security | MACOS-05, MACOS-06, MACOS-07, MACOS-08, NET-01, NET-02, NET-03, NET-04, NET-05, NET-06, NET-07, NET-08, NET-09, SVC-01, SVC-02, SVC-06 |
| 8.24 | Use of cryptography | MACOS-01, SSH-11 |

### DISA STIG

The rules each control checks, by STIG. Controls not listed check no rule of these STIGs.

| Control | Canonical Ubuntu 22.04 LTS | Canonical Ubuntu 24.04 LTS | RHEL 8 | RHEL 9 | The STIG asks for more |
| --- | --- | --- | --- | --- | --- |
| ACC-01 |  |  | V-230534 | V-258059 |  |
| ACC-02 | V-260571 | V-270713 | V-251706 | V-258120 |  |
| ACC-03 | V-260546 | V-270731 | V-230366 | V-258041 | The STIG asks for PASS_MAX_DAYS 180 or less. |
| ACC-04 | V-260565 | V-270732 | V-230369 | V-258107 | The STIG asks for a minimum length of 15 characters. |
| ACC-05 | V-260549 | V-270690 | V-230333 | V-258054 | The STIG asks for a lock after 3 failed logins. |
| ACC-06 | V-260555 | V-270716 | V-230383 | V-258074 | The STIG asks for UMASK 077. |
| ACC-07 | V-288817 | V-288819 |  | V-258046 |  |
| ACC-08 | V-260543 | V-270720 | V-230371 | V-258045 |  |
| ACC-09 | V-260547 | V-270683 | V-230373 | V-258049 | The STIG asks for INACTIVE=35 or less. |
| ACC-11 | V-260549 | V-270690 | V-230333 | V-258054 | The STIG asks for a lock after 3 failed logins. |
| SSH-01 |  |  | V-230296 | V-257985 | The STIG asks for PermitRootLogin no, which also refuses key logins as root. |
| SSH-03 | V-260526 | V-270717 | V-230380 | V-257984 | The STIG rule also asks for PermitEmptyPasswords no and PermitUserEnvironment no (SSH-03 and SSH-10). |
| SSH-04 | V-260529 | V-270708 | V-230555 | V-258007 |  |
| SSH-06 | V-260528 | V-270743 | V-244525 | V-257996 | The STIG asks for ClientAliveInterval 600 or less. |
| SSH-07 |  |  |  | V-257992 |  |
| SSH-08 |  |  |  | V-258005 |  |
| SSH-10 | V-260526 | V-270717 | V-230330 | V-257993 | The STIG rule also asks for PermitEmptyPasswords no and PermitUserEnvironment no (SSH-03 and SSH-10). |
| SSH-11 | V-260531, V-260532 | V-270667, V-270668 | V-230251, V-230252 | V-257989, V-257991 | The STIG allows only FIPS 140-3 approved algorithms. |
| SSH-13 | V-260525 | V-270691 | V-230225 | V-257981 | The STIG asks for its own notice and consent banner text. |
| SSH-14 |  |  |  | V-257982 | The STIG asks for LogLevel VERBOSE. |
| NET-01 |  |  | V-250317 | V-257970 |  |
| NET-02 |  |  | V-244553 | V-257958 |  |
| NET-03 |  |  | V-230536 | V-257968 |  |
| NET-04 |  |  | V-244551 | V-257959 |  |
| NET-05 |  |  | V-230549 | V-257962 | The STIG asks for rp_filter 1; this control also accepts 2. |
| NET-06 | V-260522 | V-270753 |  | V-257957 |  |
| NET-07 |  |  | V-230537 | V-257966 |  |
| NET-08 |  |  | V-284948 | V-257960 |  |
| NET-09 |  |  | V-230544 | V-257972 |  |
| KRN-01 | V-260474 | V-270772 | V-230280 | V-257809 |  |
| KRN-02 | V-260472 | V-270749 | V-230269 | V-257797 |  |
| KRN-03 |  |  | V-230547 | V-257800 | The STIG asks for kptr_restrict 1; this control also accepts 2. |
| KRN-04 |  |  | V-230546 | V-257811 | The STIG asks for ptrace_scope 1; this control also accepts 2 and 3. |
| KRN-06 |  |  | V-230267, V-230268 | V-257801, V-257802 |  |
| KRN-07 |  |  | V-230313, V-230314 | V-257813, V-257814 | The STIG asks for both '* hard core 0' and systemd-coredump Storage=none; this control passes with either. |
| SVC-01 | V-260515 | V-270655 | V-244544 | V-257936 | The STIG asks for ufw to be enabled and running. The STIG asks for firewalld to be active. |
| SVC-03 | V-260482 | V-270648 | V-230487, V-230533 | V-257831, V-257835 |  |
| SVC-04 |  |  | V-230553 | V-257837 |  |
| SVC-07 | V-260540 | V-270718 | V-230503 | V-258034 | The STIG also asks for blacklist usb-storage. |
| LOG-01 | V-260591 | V-270657 | V-244542 | V-258152 |  |
| LOG-03 |  |  | V-230298 | V-258142 | The STIG asks for rsyslog; this control also accepts systemd-journald and syslog-ng. |
| FS-01 |  |  |  | V-257895 |  |
| FS-02 |  |  |  | V-257934 | The STIG asks for mode 0000. |
| FS-03 |  |  |  | V-257891 |  |
| FS-04 |  |  |  | V-257893 | The STIG asks for mode 0000. |
| FS-06 |  |  | V-230511, V-230512 | V-257866, V-257868 |  |
| FS-07 |  |  | V-230508, V-230509, V-230510 | V-257863, V-257864, V-257865 |  |
| FS-09 | V-260513 | V-270750 | V-230243 | V-257929 |  |
| FS-10 |  |  | V-230326, V-230327 | V-257930, V-257931 |  |
| FS-13 |  |  | V-230321 | V-257890 |  |
| UPD-03 | V-260476 | V-270695 | V-230264 | V-257822 |  |
| TIME-01 |  |  |  | V-257944 | The STIG asks for chronyd; this control accepts any time service. |
| MAC-01 | V-260557 | V-270660 | V-230240 | V-258078 | The STIG asks for apparmor.service to be enabled and active. |
