package compliance

// Framework IDs.
const (
	NIST  = "nist-800-53"
	PCI   = "pci-dss-4"
	HIPAA = "hipaa"
	ISO   = "iso-27001"
	// STIG is the DISA STIG for the audited machine's operating system
	// (1.24.0 and later); its rules come from the controls' own mapping.
	STIG = "disa-stig"
)

var frameworks = []Framework{
	{ID: NIST, Name: "NIST SP 800-53 Rev. 5", Short: "NIST 800-53", Requirements: map[string]string{
		"AC-2": "Account management", "AC-2(3)": "Disable accounts", "AC-3": "Access enforcement", "AC-3(3)": "Mandatory access control",
		"AC-4": "Information flow enforcement", "AC-6": "Least privilege", "AC-7": "Unsuccessful logon attempts", "AC-8": "System use notification",
		"AC-12": "Session termination", "AC-17": "Remote access", "AU-2": "Event logging", "AU-8": "Time stamps",
		"AU-9": "Protection of audit information", "AU-11": "Audit record retention", "AU-12": "Audit record generation",
		"CM-6": "Configuration settings", "CM-7": "Least functionality", "CM-14": "Signed components", "IA-2": "Identification and authentication",
		"IA-5": "Authenticator management", "IA-5(1)": "Password-based authentication", "MP-7": "Media use", "RA-5": "Vulnerability monitoring and scanning",
		"SC-5": "Denial-of-service protection", "SC-7": "Boundary protection", "SC-8": "Transmission confidentiality and integrity",
		"SC-10": "Network disconnect", "SC-13": "Cryptographic protection", "SC-28": "Protection of information at rest", "SC-39": "Process isolation", "SI-2": "Flaw remediation",
		"SI-3": "Malicious code protection", "SI-4": "System monitoring", "SI-7": "Software, firmware and information integrity", "SI-16": "Memory protection",
	}},
	{ID: PCI, Name: "PCI DSS v4.0", Short: "PCI DSS", Requirements: map[string]string{
		"1.3.1": "Inbound traffic to the cardholder data environment is restricted", "1.3.2": "Outbound traffic from the cardholder data environment is restricted",
		"2.2.2": "Vendor default accounts are managed", "2.2.4": "Only necessary services and functions are enabled",
		"2.2.5": "Insecure services are justified and secured", "2.2.6": "System security parameters prevent misuse",
		"2.2.7": "Administrative access is encrypted", "5.2.1": "Anti-malware is deployed", "5.3.2": "Anti-malware scans run",
		"6.3.3": "Security patches are installed", "8.2.1": "Every user has a unique ID", "8.2.2": "Shared and generic accounts are controlled",
		"8.2.6": "Inactive accounts are removed or disabled", "8.2.8": "Idle sessions require signing in again",
		"8.3.1": "Users are authenticated", "8.3.2": "Authentication factors are unreadable when stored", "8.3.4": "Failed logins lock the account",
		"8.3.6": "Passwords have at least 12 characters", "8.3.7": "Recent passwords can't be reused", "8.3.9": "Passwords change at least every 90 days",
		"10.2.1": "Audit logs are enabled", "10.3.1": "Read access to audit logs is limited", "10.5.1": "Audit logs are retained",
		"10.6.1": "Clocks are synchronized", "11.3.1": "Internal vulnerability scans run", "11.5.2": "Changes to critical files are detected",
	}},
	{ID: HIPAA, Name: "HIPAA Security Rule (45 CFR 164 Subpart C)", Short: "HIPAA", Requirements: map[string]string{
		"164.308(a)(1)(ii)(A)": "Risk analysis", "164.308(a)(5)(ii)(B)": "Protection from malicious software",
		"164.308(a)(5)(ii)(C)": "Log-in monitoring", "164.308(a)(5)(ii)(D)": "Password management",
		"164.310(d)(1)": "Device and media controls", "164.312(a)(1)": "Access control", "164.312(a)(2)(i)": "Unique user identification",
		"164.312(a)(2)(iii)": "Automatic logoff", "164.312(a)(2)(iv)": "Encryption and decryption", "164.312(b)": "Audit controls", "164.312(c)(1)": "Integrity",
		"164.312(d)": "Person or entity authentication", "164.312(e)(1)": "Transmission security",
	}},
	{ID: ISO, Name: "ISO/IEC 27001:2022 Annex A", Short: "ISO 27001", Requirements: map[string]string{
		"5.16": "Identity management", "5.17": "Authentication information", "5.18": "Access rights", "7.10": "Storage media",
		"8.2": "Privileged access rights", "8.3": "Information access restriction", "8.5": "Secure authentication",
		"8.7": "Protection against malware", "8.8": "Management of technical vulnerabilities", "8.9": "Configuration management",
		"8.15": "Logging", "8.16": "Monitoring activities", "8.17": "Clock synchronization", "8.19": "Installation of software on operational systems",
		"8.20": "Networks security", "8.24": "Use of cryptography",
	}},
	{ID: STIG, Name: "DISA STIG for the machine's operating system", Short: "DISA STIG"},
}

// checkTitles name the checks that count as evidence alongside controls.
var checkTitles = map[string]string{
	"CHECK-packages":  "No critical or high vulnerability has a fix waiting to be installed",
	"CHECK-integrity": "System files match what their packages installed",
	"CHECK-malware":   "No malware or compromise indicators were found",
	"CHECK-antivirus": "The antivirus scan found nothing",
	"CHECK-yara":      "The advanced antivirus scan found nothing",
}

type refs map[string][]string

// m builds one control's references: NIST, PCI DSS, HIPAA, ISO 27001.
func m(nistIDs, pciIDs, hipaaIDs, isoIDs []string) refs {
	return refs{NIST: nistIDs, PCI: pciIDs, HIPAA: hipaaIDs, ISO: isoIDs}
}

func l(ids ...string) []string { return ids }

// mapping is each control's or check's requirements per framework.
var mapping = map[string]refs{
	"ACC-01": m(l("AC-6", "IA-2"), l("8.2.1"), l("164.312(a)(2)(i)"), l("8.2")),
	"ACC-02": m(l("IA-5"), l("8.3.1"), l("164.312(d)"), l("5.17")),
	"ACC-03": m(l("IA-5(1)"), l("8.3.9"), l("164.308(a)(5)(ii)(D)"), l("5.17")),
	"ACC-04": m(l("IA-5(1)"), l("8.3.6"), l("164.308(a)(5)(ii)(D)"), l("5.17")),
	"ACC-05": m(l("AC-7"), l("8.3.4"), l("164.308(a)(5)(ii)(C)"), l("8.5")),
	"ACC-06": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(a)(1)"), l("8.9")),
	"ACC-07": m(l("AC-2", "CM-6"), l("2.2.2"), l("164.312(a)(1)"), l("5.18")),
	"ACC-08": m(l("AC-2", "IA-2"), l("8.2.1"), l("164.312(a)(2)(i)"), l("5.16")),
	"ACC-09": m(l("AC-2(3)"), l("8.2.6"), nil, l("5.18")),
	"ACC-10": m(l("IA-5(1)"), l("8.3.7"), l("164.308(a)(5)(ii)(D)"), l("5.17")),
	"ACC-11": m(l("AC-7"), l("8.3.4"), l("164.308(a)(5)(ii)(C)"), l("8.5")),

	"SSH-01": m(l("AC-6", "AC-17"), l("2.2.7", "8.2.2"), l("164.312(a)(1)"), l("8.2")),
	"SSH-02": m(l("IA-2", "AC-17"), l("8.3.1"), l("164.312(d)"), l("8.5")),
	"SSH-03": m(l("IA-5"), l("8.3.1"), l("164.312(d)"), l("8.5")),
	"SSH-04": m(l("CM-7"), l("2.2.4"), l("164.312(a)(1)"), l("8.9")),
	"SSH-05": m(l("AC-7"), l("8.3.4"), l("164.308(a)(5)(ii)(C)"), l("8.5")),
	"SSH-06": m(l("AC-12", "SC-10"), l("8.2.8"), l("164.312(a)(2)(iii)"), l("8.5")),
	"SSH-07": m(l("IA-2"), l("8.3.1"), l("164.312(d)"), l("8.5")),
	"SSH-08": m(l("IA-2"), l("8.3.1"), l("164.312(d)"), l("8.5")),
	"SSH-09": m(l("AC-17", "SC-5"), l("2.2.6"), nil, l("8.9")),
	"SSH-10": m(l("CM-6"), l("2.2.6"), l("164.312(a)(1)"), l("8.9")),
	"SSH-11": m(l("SC-8", "SC-13"), l("2.2.7"), l("164.312(e)(1)"), l("8.24")),
	"SSH-12": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(a)(1)"), l("8.9")),
	"SSH-13": m(l("AC-8"), nil, nil, nil),
	"SSH-14": m(l("AU-2", "AU-12"), l("10.2.1"), l("164.312(b)"), l("8.15")),

	"NET-01": m(l("AC-4", "SC-7"), l("2.2.6"), nil, l("8.20")),
	"NET-02": m(l("SC-7", "CM-6"), l("2.2.6"), nil, l("8.20")),
	"NET-03": m(l("SC-7", "CM-6"), l("2.2.6"), nil, l("8.20")),
	"NET-04": m(l("SC-7", "CM-6"), l("2.2.6"), nil, l("8.20")),
	"NET-05": m(l("SC-7", "CM-6"), l("2.2.6"), nil, l("8.20")),
	"NET-06": m(l("SC-5"), l("2.2.6"), nil, l("8.20")),
	"NET-07": m(l("SC-5", "CM-6"), l("2.2.6"), nil, l("8.20")),
	"NET-08": m(l("AU-2", "SC-7"), l("2.2.6"), nil, l("8.20")),
	"NET-09": m(l("SC-7", "CM-6"), l("2.2.6"), nil, l("8.20")),

	"KRN-01": m(l("SI-16"), l("2.2.6"), nil, l("8.9")),
	"KRN-02": m(l("CM-6"), l("2.2.6"), nil, l("8.9")),
	"KRN-03": m(l("CM-6", "SI-16"), l("2.2.6"), nil, l("8.9")),
	"KRN-04": m(l("SC-39"), l("2.2.6"), nil, l("8.9")),
	"KRN-05": m(l("CM-6"), l("2.2.6"), nil, l("8.9")),
	"KRN-06": m(l("AC-3", "CM-6"), l("2.2.6"), nil, l("8.9")),
	"KRN-07": m(l("CM-6"), l("2.2.6"), nil, l("8.9")),

	"SVC-01": m(l("SC-7"), l("1.3.1", "1.3.2"), l("164.312(e)(1)"), l("8.20")),
	"SVC-02": m(l("CM-7", "SC-7"), l("1.3.1", "2.2.4"), l("164.312(a)(1)"), l("8.20")),
	"SVC-03": m(l("CM-7", "SC-8"), l("2.2.4", "2.2.5", "2.2.7"), l("164.312(e)(1)"), l("8.9")),
	"SVC-04": m(l("CM-7"), l("2.2.4"), nil, l("8.9")),
	"SVC-05": m(l("CM-7"), l("2.2.4"), nil, l("8.9")),
	"SVC-06": m(l("CM-7", "SC-7"), l("2.2.4"), nil, l("8.20")),
	"SVC-07": m(l("MP-7"), nil, l("164.310(d)(1)"), l("7.10")),

	"LOG-01": m(l("AU-2", "AU-12"), l("10.2.1"), l("164.312(b)"), l("8.15")),
	"LOG-02": m(l("AU-2", "AU-12"), l("10.2.1"), l("164.312(b)"), l("8.15")),
	"LOG-03": m(l("AU-12"), l("10.2.1"), l("164.312(b)"), l("8.15")),
	"LOG-04": m(l("AU-9", "AU-11"), l("10.5.1"), l("164.312(b)"), l("8.15")),
	"LOG-05": m(l("AU-9"), l("10.3.1"), l("164.312(b)"), l("8.15")),

	"FS-01": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(a)(1)", "164.312(c)(1)"), l("8.9")),
	"FS-02": m(l("AC-3", "IA-5"), l("2.2.6", "8.3.2"), l("164.312(a)(1)"), l("5.17", "8.9")),
	"FS-03": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(a)(1)"), l("8.9")),
	"FS-04": m(l("AC-3", "IA-5"), l("2.2.6", "8.3.2"), l("164.312(a)(1)"), l("5.17", "8.9")),
	"FS-05": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(c)(1)"), l("8.9")),
	"FS-06": m(l("CM-6", "CM-7"), l("2.2.6"), nil, l("8.9")),
	"FS-07": m(l("CM-6", "CM-7"), l("2.2.6"), nil, l("8.9")),
	"FS-08": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(c)(1)"), l("8.9")),
	"FS-09": m(l("AC-3", "CM-6"), l("2.2.6"), l("164.312(c)(1)"), l("8.9")),
	"FS-10": m(l("AC-3", "CM-6"), l("2.2.6"), nil, l("8.9")),
	"FS-11": m(l("AC-6", "CM-6"), l("2.2.6"), l("164.312(c)(1)"), l("8.9")),
	"FS-12": m(l("AC-3", "CM-6"), l("2.2.6"), nil, l("8.9")),
	"FS-13": m(l("AC-3"), nil, l("164.312(a)(1)"), l("8.3")),

	"UPD-01": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"UPD-02": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"UPD-03": m(l("CM-14", "SI-7"), nil, l("164.312(c)(1)"), l("8.19")),

	"TIME-01": m(l("AU-8"), l("10.6.1"), l("164.312(b)"), l("8.17")),
	"TIME-02": m(l("AU-8"), l("10.6.1"), l("164.312(b)"), l("8.17")),

	"MAC-01": m(l("AC-3(3)", "SC-39"), l("2.2.6"), l("164.312(a)(1)"), l("8.9")),

	// The macOS baseline.
	"MACOS-01": m(l("SC-28"), nil, l("164.312(a)(2)(iv)"), l("8.24")),
	"MACOS-02": m(l("SI-7", "CM-6"), l("2.2.6"), l("164.312(c)(1)"), l("8.9")),
	"MACOS-03": m(l("CM-14", "SI-3"), l("5.2.1"), l("164.308(a)(5)(ii)(B)"), l("8.7", "8.19")),
	"MACOS-04": m(l("SI-3"), l("5.2.1"), l("164.308(a)(5)(ii)(B)"), l("8.7")),
	"MACOS-05": m(l("SC-7"), l("1.3.1"), l("164.312(e)(1)"), l("8.20")),
	"MACOS-06": m(l("SC-7"), l("1.3.1"), nil, l("8.20")),
	"MACOS-07": m(l("AC-17", "CM-7"), l("2.2.4"), l("164.312(a)(1)"), l("8.20")),
	"MACOS-08": m(l("AC-17", "CM-7"), l("2.2.4"), l("164.312(a)(1)"), l("8.20")),
	"MACOS-09": m(l("CM-7"), l("2.2.4"), nil, l("8.3")),
	"MACOS-10": m(l("AC-2", "IA-2"), l("8.2.2"), l("164.312(a)(2)(i)"), l("5.16")),
	"MACOS-11": m(l("IA-2"), l("8.3.1"), l("164.312(d)"), l("8.5")),
	"MACOS-12": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"MACOS-13": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"MACOS-14": m(l("SI-2", "SI-3"), l("6.3.3", "5.2.1"), l("164.308(a)(5)(ii)(B)"), l("8.7", "8.8")),
	"MACOS-15": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"MACOS-16": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"MACOS-17": m(l("SI-2"), l("6.3.3"), nil, l("8.8")),
	"MACOS-18": m(l("AU-8"), l("10.6.1"), l("164.312(b)"), l("8.17")),

	"CHECK-packages":  m(l("SI-2", "RA-5"), l("6.3.3", "11.3.1"), l("164.308(a)(1)(ii)(A)"), l("8.8")),
	"CHECK-integrity": m(l("SI-7"), l("11.5.2"), l("164.312(c)(1)"), l("8.16")),
	"CHECK-malware":   m(l("SI-3", "SI-4"), l("5.2.1"), l("164.308(a)(5)(ii)(B)"), l("8.7", "8.16")),
	"CHECK-antivirus": m(l("SI-3"), l("5.2.1", "5.3.2"), l("164.308(a)(5)(ii)(B)"), l("8.7")),
	"CHECK-yara":      m(l("SI-3"), l("5.2.1", "5.3.2"), l("164.308(a)(5)(ii)(B)"), l("8.7")),
}
