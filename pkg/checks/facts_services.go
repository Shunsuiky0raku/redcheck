// pkg/checks/facts_services.go
package checks

import (
	"os"
	"os/exec"
	"strings"
)

// FirewalldInstalled returns "present" or "absent".
func FirewalldInstalled() (string, error) {
	// Prefer rpm on Rocky/RHEL; fall back to dnf if rpm isn't there.
	if _, err := exec.LookPath("rpm"); err == nil {
		out, _ := exec.Command("rpm", "-q", "firewalld").CombinedOutput()
		s := string(out)
		if strings.Contains(s, "is not installed") || strings.TrimSpace(s) == "" {
			return "absent", nil
		}
		return "present", nil
	}
	// Fallback: dnf list installed
	if _, err := exec.LookPath("dnf"); err == nil {
		out, _ := exec.Command("dnf", "-q", "list", "installed", "firewalld").CombinedOutput()
		if strings.Contains(string(out), "Installed Packages") {
			return "present", nil
		}
		return "absent", nil
	}
	// Last resort: check file existence of unit as a weak signal
	if _, err := os.Stat("/usr/lib/systemd/system/firewalld.service"); err == nil {
		return "present", nil
	}
	return "absent", nil
}

// FirewalldState returns one of:
// "enabled_active", "enabled_inactive", "disabled_active", "disabled_inactive".
func FirewalldState() (string, error) {
	en, _ := exec.Command("systemctl", "is-enabled", "firewalld").Output()
	ac, _ := exec.Command("systemctl", "is-active", "firewalld").Output()
	e := strings.TrimSpace(string(en))
	a := strings.TrimSpace(string(ac))
	switch {
	case e == "enabled" && a == "active":
		return "enabled_active", nil
	case e == "enabled" && a != "active":
		return "enabled_inactive", nil
	case e != "enabled" && a == "active":
		return "disabled_active", nil
	default:
		return "disabled_inactive", nil
	}
}

// CryptoPolicy returns "NOT_LEGACY", "LEGACY", or "unknown".
func CryptoPolicy() (string, error) {
	// Try the command first
	if _, err := exec.LookPath("update-crypto-policies"); err == nil {
		out, err := exec.Command("update-crypto-policies", "--show").Output()
		if err == nil {
			p := strings.TrimSpace(string(out))
			if strings.EqualFold(p, "LEGACY") {
				return "LEGACY", nil
			}
			return "NOT_LEGACY", nil
		}
	}
	// Fallback: read state file if present
	if b, err := os.ReadFile("/etc/crypto-policies/state/current"); err == nil {
		p := strings.TrimSpace(string(b))
		if strings.EqualFold(p, "LEGACY") {
			return "LEGACY", nil
		}
		return "NOT_LEGACY", nil
	}
	return "unknown", nil
}
