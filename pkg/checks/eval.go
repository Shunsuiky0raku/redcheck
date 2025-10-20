// pkg/checks/eval.go
package checks

import "strings"

type CheckResult struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Status      string `json:"status"` // pass|fail|error|na
	Observed    string `json:"observed"`
	Expected    string `json:"expected"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// Implement scoring.Result
func (c CheckResult) GetID() string       { return c.ID }
func (c CheckResult) GetSeverity() string { return c.Severity }
func (c CheckResult) GetStatus() string   { return c.Status }
func (c CheckResult) GetCategory() string { return c.Category }

func Evaluate(rule Rule) CheckResult {
	res := CheckResult{
		ID:          rule.ID,
		Title:       rule.Title,
		Category:    rule.Category,
		Severity:    rule.Severity,
		Remediation: rule.Remediation,
	}

	// Fetch observed value
	var (
		val string
		err error
	)
	switch rule.Fact {
	case "ssh.permit_root_login":
		val, err = SSHPermitRootLogin()
	case "sysctl.net.ipv6.conf.all.accept_redirects":
		val, err = SysctlValue("net.ipv6.conf.all.accept_redirects")
	case "mount.devshm_options":
		val, err = MountOptions("/dev/shm")
	case "pkg.firewalld_installed":
		val, err = FirewalldInstalled()
	case "svc.firewalld_state":
		val, err = FirewalldState()
	case "crypto.policy":
		val, err = CryptoPolicy()
	case "mount.tmp_options":
		val, err = MountOptions("/tmp")
	case "mount.vartmp_options":
		val, err = MountOptions("/var/tmp")
	case "sudo.use_pty":
		val, err = SudoUsePTY()
	case "sudo.logfile":
		val, err = SudoLogfile()
	case "acct.uid0_unique":
		val, err = UID0Unique()
	case "ssh.x11_forwarding":
		val, err = SSHX11Forwarding()
	case "ssh.banner":
		val, err = SSHBannerPresent()
	case "sysctl.net.ipv6.conf.all.accept_ra":
		val, err = SysctlValue("net.ipv6.conf.all.accept_ra")
	case "sysctl.net.ipv6.conf.all.accept_source_route":
		val, err = SysctlValue("net.ipv6.conf.all.accept_source_route")
	case "sysctl.net.ipv4.tcp_syncookies":
		val, err = SysctlValue("net.ipv4.tcp_syncookies")
	case "sudo.timestamp_timeout_sane":
		val, err = SudoTimestampTimeoutSane()
	case "sudo.nopasswd_wildcard_forbidden":
		val, err = SudoNoPasswdWildcardForbidden()
	case "pam.pwquality_present":
		val, err = PamPwqualityPresent()
	case "pam.pwhistory_present":
		val, err = PamPwhistoryPresent()
	case "pam.faillock_present":
		val, err = PamFaillockPresent()
	case "sysctl.net.ipv6.conf.default.accept_redirects":
		val, err = SysctlValueDefault("net.ipv6.conf.default.accept_redirects")
	case "sysctl.net.ipv6.conf.default.accept_ra":
		val, err = SysctlValueDefault("net.ipv6.conf.default.accept_ra")
	case "sysctl.net.ipv6.conf.default.accept_source_route":
		val, err = SysctlValueDefault("net.ipv6.conf.default.accept_source_route")
	case "login.defs.pass_max_days_ok":
		val, err = LoginDefsPassMaxDaysOK()
	case "login.defs.pass_min_days_ok":
		val, err = LoginDefsPassMinDaysOK()
	case "login.defs.pass_warn_age_ok":
		val, err = LoginDefsPassWarnAgeOK()
	case "useradd.inactive_ok":
		val, err = UseraddInactiveOK()

	default:
		val = "unknown"
	}
	res.Observed = val

	// Error collecting the fact
	if err != nil {
		res.Status = "error"
		res.Expected = firstNonEmpty(rule.Expected, strings.Join(rule.ExpectedAll, ","))
		return res
	}

	// Compare observed vs expected
	pass := false
	if rule.Expected != "" {
		pass = (val == rule.Expected)
	} else if len(rule.ExpectedAll) > 0 {
		pass = containsAll(val, rule.ExpectedAll)
	}

	res.Status = map[bool]string{true: "pass", false: "fail"}[pass]
	res.Expected = firstNonEmpty(rule.Expected, strings.Join(rule.ExpectedAll, ","))
	return res
}

func containsAll(hay string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(hay, n) {
			return false
		}
	}
	return true
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
