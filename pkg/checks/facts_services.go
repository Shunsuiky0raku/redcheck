// pkg/checks/facts_services.go
package checks

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

// internal helpers
func runOut(name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = nil
	err := cmd.Run()
	return buf.String(), err
}

// FirewalldInstalled returns "present"/"absent" with multiple strategies.
func FirewalldInstalled() (string, error) {
	// 1) systemctl knows about the unit?
	if out, _ := runOut("systemctl", "list-unit-files", "firewalld.service"); strings.Contains(out, "firewalld.service") {
		return "present", nil
	}
	// 2) rpm database (RHEL/Rocky)
	if out, _ := runOut("rpm", "-q", "firewalld"); strings.Contains(out, "firewalld") && !strings.Contains(out, "not installed") {
		return "present", nil
	}
	// 3) which firewalld (binary present)
	if _, err := exec.LookPath("firewalld"); err == nil {
		return "present", nil
	}
	return "absent", nil
}

// FirewalldState returns:
//
//	"enabled_active", "active_not_enabled", "enabled_inactive", "disabled_inactive"
func FirewalldState() (string, error) {
	// if unit not present at all, treat as disabled_inactive
	out, _ := runOut("systemctl", "list-unit-files", "firewalld.service")
	if !strings.Contains(out, "firewalld.service") {
		return "disabled_inactive", nil
	}
	enabled := false
	active := false
	if out, _ := runOut("systemctl", "is-enabled", "firewalld"); strings.Contains(out, "enabled") {
		enabled = true
	}
	if out, _ := runOut("systemctl", "is-active", "firewalld"); strings.Contains(out, "active") {
		active = true
	}
	switch {
	case enabled && active:
		return "enabled_active", nil
	case active && !enabled:
		return "active_not_enabled", nil
	case enabled && !active:
		return "enabled_inactive", nil
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
