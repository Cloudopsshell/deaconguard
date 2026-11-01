package checks

import (
	"sort"
	"strings"
)

// STIGRule is a rule of a DISA STIG that a baseline control checks on the
// machine's operating system (1.24.0 and later).
type STIGRule struct {
	// STIG names the guide, such as "DISA RHEL 9 STIG".
	STIG string `json:"stig"`
	// Rule is the rule's vulnerability ID, such as "V-257985".
	Rule string `json:"rule"`
	// Note says what the STIG asks for beyond what the control checks, so
	// a passed control isn't taken for a passed STIG rule; empty when the
	// control checks what the rule does.
	Note string `json:"note,omitempty"`
}

// STIGGuide is a DISA STIG the Linux baseline is mapped to.
type STIGGuide struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Release string `json:"release"`
}

// The STIGs the Linux baseline is mapped to. DISA publishes them openly;
// the mapping is DeaconGuard's own.
var (
	stigUbuntu22 = STIGGuide{Key: "ubuntu-22.04", Name: "DISA Canonical Ubuntu 22.04 LTS STIG", Release: "V2R10, 30 September 2026"}
	stigUbuntu24 = STIGGuide{Key: "ubuntu-24.04", Name: "DISA Canonical Ubuntu 24.04 LTS STIG", Release: "V1R7, 30 September 2026"}
	stigRHEL8    = STIGGuide{Key: "rhel-8", Name: "DISA RHEL 8 STIG", Release: "V2R9, 30 September 2026"}
	stigRHEL9    = STIGGuide{Key: "rhel-9", Name: "DISA RHEL 9 STIG", Release: "V2R10, 30 September 2026"}
)

// STIGGuides lists the STIGs the Linux baseline is mapped to.
func STIGGuides() []STIGGuide { return []STIGGuide{stigUbuntu22, stigUbuntu24, stigRHEL8, stigRHEL9} }

// STIGFor is the STIG for the operating system a scan reported, such as
// "Ubuntu 24.04 LTS" or "Rocky Linux 9.4". Rocky Linux and AlmaLinux are
// rebuilds of RHEL, so the RHEL STIG is the one their admins work from.
func STIGFor(os string) (STIGGuide, bool) {
	switch {
	case strings.HasPrefix(os, "Ubuntu 22.04"):
		return stigUbuntu22, true
	case strings.HasPrefix(os, "Ubuntu 24.04"):
		return stigUbuntu24, true
	}
	for _, prefix := range []string{"Red Hat Enterprise Linux ", "Rocky Linux ", "AlmaLinux "} {
		if version, found := strings.CutPrefix(os, prefix); found {
			switch {
			case version == "8" || strings.HasPrefix(version, "8."):
				return stigRHEL8, true
			case version == "9" || strings.HasPrefix(version, "9."):
				return stigRHEL9, true
			}
		}
	}
	return STIGGuide{}, false
}

// STIGRules lists the rules of the STIG for os that control checks.
func STIGRules(os, control string) []STIGRule {
	guide, ok := STIGFor(os)
	if !ok {
		return nil
	}
	var rules []STIGRule
	for _, rule := range baselineSTIG[control][guide.Key] {
		rules = append(rules, STIGRule{STIG: guide.Name, Rule: rule.rule, Note: rule.note})
	}
	return rules
}

// STIGControls lists, for each rule of guide the baseline checks, the
// controls that check it, in rule order.
func STIGControls(guide STIGGuide) (rules []string, controls map[string][]string) {
	controls = map[string][]string{}
	for control, guides := range baselineSTIG {
		for _, rule := range guides[guide.Key] {
			if len(controls[rule.rule]) == 0 {
				rules = append(rules, rule.rule)
			}
			controls[rule.rule] = append(controls[rule.rule], control)
		}
	}
	sort.Strings(rules)
	for _, list := range controls {
		sort.Strings(list)
	}
	return rules, controls
}

// STIGTitle is a mapped STIG rule's title, as DISA publishes it.
func STIGTitle(rule string) string { return stigTitles[rule] }

type stigRule struct{ rule, note string }

// Notes for rules that ask for more than the control checks.
const (
	noteMaxDays      = "The STIG asks for PASS_MAX_DAYS 180 or less."
	noteMinLen       = "The STIG asks for a minimum length of 15 characters."
	noteDeny         = "The STIG asks for a lock after 3 failed logins."
	noteUmask        = "The STIG asks for UMASK 077."
	noteInactive     = "The STIG asks for INACTIVE=35 or less."
	noteRootLogin    = "The STIG asks for PermitRootLogin no, which also refuses key logins as root."
	noteClientAlive  = "The STIG asks for ClientAliveInterval 600 or less."
	noteFIPS         = "The STIG allows only FIPS 140-3 approved algorithms."
	noteBanner       = "The STIG asks for its own notice and consent banner text."
	noteVerbose      = "The STIG asks for LogLevel VERBOSE."
	noteUbuntuSSH    = "The STIG rule also asks for PermitEmptyPasswords no and PermitUserEnvironment no (SSH-03 and SSH-10)."
	noteRPFilter     = "The STIG asks for rp_filter 1; this control also accepts 2."
	noteKptr         = "The STIG asks for kptr_restrict 1; this control also accepts 2."
	notePtrace       = "The STIG asks for ptrace_scope 1; this control also accepts 2 and 3."
	noteCore         = "The STIG asks for both '* hard core 0' and systemd-coredump Storage=none; this control passes with either."
	noteUFW          = "The STIG asks for ufw to be enabled and running."
	noteFirewalld    = "The STIG asks for firewalld to be active."
	noteBlacklist    = "The STIG also asks for blacklist usb-storage."
	noteRsyslog      = "The STIG asks for rsyslog; this control also accepts systemd-journald and syslog-ng."
	noteModeZero     = "The STIG asks for mode 0000."
	noteChrony       = "The STIG asks for chronyd; this control accepts any time service."
	noteAppArmorUnit = "The STIG asks for apparmor.service to be enabled and active."
)

// baselineSTIG maps each Linux baseline control to the STIG rules it
// checks, per STIG. A control is mapped only where it checks the same
// setting as the rule; controls with no such rule are left out.
var baselineSTIG = map[string]map[string][]stigRule{
	"ACC-01": {"rhel-8": {{"V-230534", ""}}, "rhel-9": {{"V-258059", ""}}},
	"ACC-02": {"ubuntu-22.04": {{"V-260571", ""}}, "ubuntu-24.04": {{"V-270713", ""}}, "rhel-8": {{"V-251706", ""}}, "rhel-9": {{"V-258120", ""}}},
	"ACC-03": {"ubuntu-22.04": {{"V-260546", noteMaxDays}}, "ubuntu-24.04": {{"V-270731", noteMaxDays}}, "rhel-8": {{"V-230366", noteMaxDays}}, "rhel-9": {{"V-258041", noteMaxDays}}},
	"ACC-04": {"ubuntu-22.04": {{"V-260565", noteMinLen}}, "ubuntu-24.04": {{"V-270732", noteMinLen}}, "rhel-8": {{"V-230369", noteMinLen}}, "rhel-9": {{"V-258107", noteMinLen}}},
	"ACC-05": {"ubuntu-22.04": {{"V-260549", noteDeny}}, "ubuntu-24.04": {{"V-270690", noteDeny}}, "rhel-8": {{"V-230333", noteDeny}}, "rhel-9": {{"V-258054", noteDeny}}},
	"ACC-06": {"ubuntu-22.04": {{"V-260555", noteUmask}}, "ubuntu-24.04": {{"V-270716", noteUmask}}, "rhel-8": {{"V-230383", noteUmask}}, "rhel-9": {{"V-258074", noteUmask}}},
	"ACC-07": {"ubuntu-22.04": {{"V-288817", ""}}, "ubuntu-24.04": {{"V-288819", ""}}, "rhel-9": {{"V-258046", ""}}},
	"ACC-08": {"ubuntu-22.04": {{"V-260543", ""}}, "ubuntu-24.04": {{"V-270720", ""}}, "rhel-8": {{"V-230371", ""}}, "rhel-9": {{"V-258045", ""}}},
	"ACC-09": {"ubuntu-22.04": {{"V-260547", noteInactive}}, "ubuntu-24.04": {{"V-270683", noteInactive}}, "rhel-8": {{"V-230373", noteInactive}}, "rhel-9": {{"V-258049", noteInactive}}},
	"ACC-11": {"ubuntu-22.04": {{"V-260549", noteDeny}}, "ubuntu-24.04": {{"V-270690", noteDeny}}, "rhel-8": {{"V-230333", noteDeny}}, "rhel-9": {{"V-258054", noteDeny}}},
	"SSH-01": {"rhel-8": {{"V-230296", noteRootLogin}}, "rhel-9": {{"V-257985", noteRootLogin}}},
	"SSH-03": {"ubuntu-22.04": {{"V-260526", noteUbuntuSSH}}, "ubuntu-24.04": {{"V-270717", noteUbuntuSSH}}, "rhel-8": {{"V-230380", ""}}, "rhel-9": {{"V-257984", ""}}},
	"SSH-04": {"ubuntu-22.04": {{"V-260529", ""}}, "ubuntu-24.04": {{"V-270708", ""}}, "rhel-8": {{"V-230555", ""}}, "rhel-9": {{"V-258007", ""}}},
	"SSH-06": {"ubuntu-22.04": {{"V-260528", noteClientAlive}}, "ubuntu-24.04": {{"V-270743", noteClientAlive}}, "rhel-8": {{"V-244525", noteClientAlive}}, "rhel-9": {{"V-257996", noteClientAlive}}},
	"SSH-07": {"rhel-9": {{"V-257992", ""}}},
	"SSH-08": {"rhel-9": {{"V-258005", ""}}},
	"SSH-10": {"ubuntu-22.04": {{"V-260526", noteUbuntuSSH}}, "ubuntu-24.04": {{"V-270717", noteUbuntuSSH}}, "rhel-8": {{"V-230330", ""}}, "rhel-9": {{"V-257993", ""}}},
	"SSH-11": {
		"ubuntu-22.04": {{"V-260531", noteFIPS}, {"V-260532", noteFIPS}}, "ubuntu-24.04": {{"V-270667", noteFIPS}, {"V-270668", noteFIPS}},
		"rhel-8": {{"V-230251", noteFIPS}, {"V-230252", noteFIPS}}, "rhel-9": {{"V-257989", noteFIPS}, {"V-257991", noteFIPS}},
	},
	"SSH-13": {"ubuntu-22.04": {{"V-260525", noteBanner}}, "ubuntu-24.04": {{"V-270691", noteBanner}}, "rhel-8": {{"V-230225", noteBanner}}, "rhel-9": {{"V-257981", noteBanner}}},
	"SSH-14": {"rhel-9": {{"V-257982", noteVerbose}}},
	"NET-01": {"rhel-8": {{"V-250317", ""}}, "rhel-9": {{"V-257970", ""}}},
	"NET-02": {"rhel-8": {{"V-244553", ""}}, "rhel-9": {{"V-257958", ""}}},
	"NET-03": {"rhel-8": {{"V-230536", ""}}, "rhel-9": {{"V-257968", ""}}},
	"NET-04": {"rhel-8": {{"V-244551", ""}}, "rhel-9": {{"V-257959", ""}}},
	"NET-05": {"rhel-8": {{"V-230549", noteRPFilter}}, "rhel-9": {{"V-257962", noteRPFilter}}},
	"NET-06": {"ubuntu-22.04": {{"V-260522", ""}}, "ubuntu-24.04": {{"V-270753", ""}}, "rhel-9": {{"V-257957", ""}}},
	"NET-07": {"rhel-8": {{"V-230537", ""}}, "rhel-9": {{"V-257966", ""}}},
	"NET-08": {"rhel-8": {{"V-284948", ""}}, "rhel-9": {{"V-257960", ""}}},
	"NET-09": {"rhel-8": {{"V-230544", ""}}, "rhel-9": {{"V-257972", ""}}},
	"KRN-01": {"ubuntu-22.04": {{"V-260474", ""}}, "ubuntu-24.04": {{"V-270772", ""}}, "rhel-8": {{"V-230280", ""}}, "rhel-9": {{"V-257809", ""}}},
	"KRN-02": {"ubuntu-22.04": {{"V-260472", ""}}, "ubuntu-24.04": {{"V-270749", ""}}, "rhel-8": {{"V-230269", ""}}, "rhel-9": {{"V-257797", ""}}},
	"KRN-03": {"rhel-8": {{"V-230547", noteKptr}}, "rhel-9": {{"V-257800", noteKptr}}},
	"KRN-04": {"rhel-8": {{"V-230546", notePtrace}}, "rhel-9": {{"V-257811", notePtrace}}},
	"KRN-06": {"rhel-8": {{"V-230267", ""}, {"V-230268", ""}}, "rhel-9": {{"V-257801", ""}, {"V-257802", ""}}},
	"KRN-07": {"rhel-8": {{"V-230313", noteCore}, {"V-230314", noteCore}}, "rhel-9": {{"V-257813", noteCore}, {"V-257814", noteCore}}},
	"SVC-01": {"ubuntu-22.04": {{"V-260515", noteUFW}}, "ubuntu-24.04": {{"V-270655", noteUFW}}, "rhel-8": {{"V-244544", noteFirewalld}}, "rhel-9": {{"V-257936", noteFirewalld}}},
	"SVC-03": {
		"ubuntu-22.04": {{"V-260482", ""}}, "ubuntu-24.04": {{"V-270648", ""}},
		"rhel-8": {{"V-230487", ""}, {"V-230533", ""}}, "rhel-9": {{"V-257831", ""}, {"V-257835", ""}},
	},
	"SVC-04":  {"rhel-8": {{"V-230553", ""}}, "rhel-9": {{"V-257837", ""}}},
	"SVC-07":  {"ubuntu-22.04": {{"V-260540", noteBlacklist}}, "ubuntu-24.04": {{"V-270718", noteBlacklist}}, "rhel-8": {{"V-230503", noteBlacklist}}, "rhel-9": {{"V-258034", noteBlacklist}}},
	"LOG-01":  {"ubuntu-22.04": {{"V-260591", ""}}, "ubuntu-24.04": {{"V-270657", ""}}, "rhel-8": {{"V-244542", ""}}, "rhel-9": {{"V-258152", ""}}},
	"LOG-03":  {"rhel-8": {{"V-230298", noteRsyslog}}, "rhel-9": {{"V-258142", noteRsyslog}}},
	"FS-01":   {"rhel-9": {{"V-257895", ""}}},
	"FS-02":   {"rhel-9": {{"V-257934", noteModeZero}}},
	"FS-03":   {"rhel-9": {{"V-257891", ""}}},
	"FS-04":   {"rhel-9": {{"V-257893", noteModeZero}}},
	"FS-06":   {"rhel-8": {{"V-230511", ""}, {"V-230512", ""}}, "rhel-9": {{"V-257866", ""}, {"V-257868", ""}}},
	"FS-07":   {"rhel-8": {{"V-230508", ""}, {"V-230509", ""}, {"V-230510", ""}}, "rhel-9": {{"V-257863", ""}, {"V-257864", ""}, {"V-257865", ""}}},
	"FS-09":   {"ubuntu-22.04": {{"V-260513", ""}}, "ubuntu-24.04": {{"V-270750", ""}}, "rhel-8": {{"V-230243", ""}}, "rhel-9": {{"V-257929", ""}}},
	"FS-10":   {"rhel-8": {{"V-230326", ""}, {"V-230327", ""}}, "rhel-9": {{"V-257930", ""}, {"V-257931", ""}}},
	"FS-13":   {"rhel-8": {{"V-230321", ""}}, "rhel-9": {{"V-257890", ""}}},
	"UPD-03":  {"ubuntu-22.04": {{"V-260476", ""}}, "ubuntu-24.04": {{"V-270695", ""}}, "rhel-8": {{"V-230264", ""}}, "rhel-9": {{"V-257822", ""}}},
	"TIME-01": {"rhel-9": {{"V-257944", noteChrony}}},
	"MAC-01":  {"ubuntu-22.04": {{"V-260557", noteAppArmorUnit}}, "ubuntu-24.04": {{"V-270660", noteAppArmorUnit}}, "rhel-8": {{"V-230240", ""}}, "rhel-9": {{"V-258078", ""}}},
}
