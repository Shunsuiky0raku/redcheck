package checks

import (
	"strings"
)

type CheckResult struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // pass|fail|error
	Observed    string `json:"observed"`
	Expected    string `json:"expected"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

func Evaluate(rule Rule) CheckResult {
	res := CheckResult{ID: rule.ID, Title: rule.Title, Severity: rule.Severity, Remediation: rule.Remediation}
	var val string
	var err error

	switch rule.Fact {
	case "ssh.permit_root_login":
		val, err = SSHPermitRootLogin()
	case "sysctl.net.ipv6.conf.all.accept_redirects":
		val, err = SysctlValue("net.ipv6.conf.all.accept_redirects")
	case "mount.devshm_options":
		val, err = MountOptions("/dev/shm")
	default:
		err = nil
		val = "unknown"
	}

	res.Observed = val
	if err != nil {
		res.Status = "error"
		res.Expected = firstNonEmpty(rule.Expected, strings.Join(rule.ExpectedAll, ","))
		return res
	}

	// comparison
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
