// pkg/checks/fix.go
package checks

import (
	"fmt"
	"sort"
	"strings"
)

// BuildFixScript builds a *non-destructive* Bash script with suggested
// remediations for failed checks. It does NOT apply any changes by itself;
// instead, it prints clearly commented steps for an administrator to review
// and execute manually.
//
// This avoids bricking systems while still giving concrete, actionable guidance.
func BuildFixScript(results []CheckResult) string {
	var b strings.Builder

	// Script header
	b.WriteString("#!/bin/bash\n\n")
	b.WriteString("set -e\n\n")
	b.WriteString("echo \"redcheck fix script (non-destructive helper)\"\n")
	b.WriteString("echo \"Review and adapt each remediation before running on production systems.\"\n\n")

	// Collect failed checks only
	var failed []CheckResult
	for _, r := range results {
		// r.Status is usually a string-like type; compare to literal
		if r.Status != "fail" {
			continue
		}
		if strings.TrimSpace(r.Remediation) == "" {
			continue
		}
		failed = append(failed, r)
	}

	if len(failed) == 0 {
		b.WriteString("echo \"No failed checks — nothing to fix.\"\n")
		return b.String()
	}

	// Sort for deterministic output: by category, then ID
	sort.SliceStable(failed, func(i, j int) bool {
		if failed[i].Category == failed[j].Category {
			return failed[i].ID < failed[j].ID
		}
		return failed[i].Category < failed[j].Category
	})

	seen := make(map[string]bool)

	for _, r := range failed {
		// Deduplicate by rule ID
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true

		title := escapeShell(r.Title)
		id := escapeShell(r.ID)

		b.WriteString(fmt.Sprintf("echo \"Fixing %s (%s)\"\n", title, id))

		// High-level info as comments
		b.WriteString("# -------------------------------------------------------------------\n")
		b.WriteString("# Rule ID    : " + r.ID + "\n")
		b.WriteString("# Title      : " + r.Title + "\n")
		b.WriteString("# Category   : " + r.Category + "\n")
		if strings.TrimSpace(r.Expected) != "" {
			b.WriteString("# Expected   : " + r.Expected + "\n")
		}
		if strings.TrimSpace(r.Observed) != "" {
			b.WriteString("# Observed   : " + r.Observed + "\n")
		}

		// Best-effort guess of where to look for the config
		if hint := guessConfigLocation(r.ID, r.Category); hint != "" {
			b.WriteString("# Likely config location(s): " + hint + "\n")
		}

		b.WriteString("# Remediation steps (manual):\n")
		for _, line := range strings.Split(r.Remediation, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			b.WriteString("#   - " + line + "\n")
		}

		b.WriteString("# TODO: Implement exact commands for your environment here.\n")
		b.WriteString("# Example:\n")
		switch {
		case strings.HasPrefix(r.ID, "CIS-5.1.") || strings.Contains(strings.ToLower(r.Title), "ssh"):
			b.WriteString("#   nano /etc/ssh/sshd_config\n")
			b.WriteString("#   # Apply the changes above, then:\n")
			b.WriteString("#   systemctl reload sshd\n")
		case strings.HasPrefix(r.ID, "CIS-4.1."):
			b.WriteString("#   dnf install -y firewalld\n")
			b.WriteString("#   systemctl enable --now firewalld\n")
		case strings.HasPrefix(r.ID, "CIS-5.2.") || strings.Contains(strings.ToLower(r.Title), "sudo"):
			b.WriteString("#   visudo\n")
			b.WriteString("#   # Add or adjust the Defaults line as described.\n")
		case strings.HasPrefix(r.ID, "CIS-1.6.1"):
			b.WriteString("#   update-crypto-policies --set DEFAULT\n")
		default:
			b.WriteString("#   # Apply the steps above based on your distro.\n")
		}

		b.WriteString("\n")
	}

	b.WriteString("echo \"All suggested remediations have been listed above.\"\n")
	b.WriteString("echo \"Review this script and convert comments into real commands where appropriate.\"\n")

	return b.String()
}

// escapeShell is a minimal helper to safely embed text in double-quoted
// shell strings.
func escapeShell(s string) string {
	// Escape existing double quotes
	return strings.ReplaceAll(s, "\"", "\\\"")
}

// guessConfigLocation tries to give the user a helpful hint about
// where the relevant configuration likely lives. It is intentionally
// heuristic and non-exhaustive.
func guessConfigLocation(id, category string) string {
	idLower := strings.ToLower(id)
	catLower := strings.ToLower(category)

	// SSH-related
	if strings.Contains(idLower, "5.1.") || strings.Contains(catLower, "auth") {
		if strings.Contains(strings.ToLower(id), "ssh") ||
			strings.Contains(strings.ToLower(id), "x11") ||
			strings.Contains(strings.ToLower(id), "banner") {
			return "/etc/ssh/sshd_config, /etc/issue.net"
		}
	}

	// Sudo-related
	if strings.Contains(idLower, "5.2.") {
		return "/etc/sudoers, /etc/sudoers.d/"
	}

	// Accounts / aging policy
	if strings.Contains(idLower, "5.4.") {
		return "/etc/login.defs, chage(1) per-user settings"
	}

	// Filesystem / mount options
	if strings.Contains(catLower, "fs_perms") {
		return "/etc/fstab, systemd mount units in /etc/systemd/system/"
	}

	// Network / sysctl
	if strings.Contains(catLower, "services") {
		return "/etc/sysctl.conf, /etc/sysctl.d/*.conf, /usr/lib/sysctl.d/*.conf"
	}

	// Recon / privilege escalation hints
	if strings.HasPrefix(id, "RC-") {
		return "Use: find(1), ls(1), and manual review of SUID/SGID binaries and $PATH dirs"
	}

	return ""
}

