package checks

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// BuildFixScript generates a semi-automatic Bash remediation script.
//
// - Only includes rules with Status == "fail" from the *current* scan
//   (so it automatically respects --all / --cis / --pe).
// - Sorts by severity (Critical → High → Medium → Low) then by rule ID.
// - For “safe-ish” rules, emits real commands guarded by a y/N prompt.
// - For dangerous rules (UID 0 abuse, SUID cleanup, etc.), emits guidance
//   and TODOs instead of destructive automation.
func BuildFixScript(results []CheckResult, w io.Writer) error {
	// Header
	fmt.Fprintln(w, "#!/bin/bash")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "set -e")
	fmt.Fprintln(w)
	fmt.Fprintln(w, `echo "redcheck semi-automatic fix script"`)
	fmt.Fprintln(w, `echo "You will be prompted before each change."`)
	fmt.Fprintln(w, `echo "Review this script before running it on production systems."`)
	fmt.Fprintln(w)

	// Filter only failed checks
	var failed []CheckResult
	for _, r := range results {
		if strings.EqualFold(r.Status, "fail") {
			failed = append(failed, r)
		}
	}

	if len(failed) == 0 {
		fmt.Fprintln(w, `echo "No failing checks detected."`)
		fmt.Fprintln(w, `echo "Nothing to fix."`)
		return nil
	}

	// Sort by severity (Critical → High → Medium → Low) then by ID
	severityRank := map[string]int{
		"Critical": 0,
		"High":     1,
		"Medium":   2,
		"Low":      3,
		"":         4,
	}

	sort.Slice(failed, func(i, j int) bool {
		si := severityRank[strings.Title(strings.ToLower(strings.TrimSpace(failed[i].Severity)))]
		sj := severityRank[strings.Title(strings.ToLower(strings.TrimSpace(failed[j].Severity)))]
		if si != sj {
			return si < sj
		}
		return failed[i].GetID() < failed[j].GetID()
	})

	// Emit one interactive block per failing rule
	for _, r := range failed {
		id := r.GetID()
		title := r.Title
		category := r.Category
		expected := r.Expected

		fmt.Fprintln(w)
		fmt.Fprintln(w, "echo")
		fmt.Fprintln(w, `echo "============================================================"`)
		fmt.Fprintf(
			w,
			"echo \"Rule     : %s (%s)\"\n",
			escapeForDoubleQuotes(title),
			escapeForDoubleQuotes(id),
		)

		if category != "" {
			fmt.Fprintf(
				w,
				"echo \"Category : %s\"\n",
				escapeForDoubleQuotes(category),
			)
		}

		if expected != "" {
			fmt.Fprintf(
				w,
				"echo \"Expected : %s\"\n",
				escapeForDoubleQuotes(expected),
			)
		}

		if r.Remediation != "" {
			fmt.Fprintf(
				w,
				"echo \"Remediation (summary): %s\"\n",
				escapeForDoubleQuotes(r.Remediation),
			)
		}

		fmt.Fprintln(w, `read -r -p "Apply this remediation? [y/N]: " ANSW`)
		fmt.Fprintln(w, `if [[ "$ANSW" =~ ^[Yy]$ ]]; then`)
		emitRuleFixBlock(w, id)
		fmt.Fprintln(w, "else")
		fmt.Fprintf(
			w,
			"  echo \"[SKIP] Skipped fix for %s\"\n",
			escapeForDoubleQuotes(id),
		)
		fmt.Fprintln(w, "fi")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, `echo "All interactive fixes processed."`)
	fmt.Fprintln(w, `echo "Re-run: sudo ./redcheck scan --all to verify the new posture."`)

	return nil
}

// escapeForDoubleQuotes makes a string safe for inclusion inside a shell "..."
func escapeForDoubleQuotes(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// emitRuleFixBlock emits the *shell* commands implementing the fix for a given rule ID.
// All commands are wrapped inside the if [[ "$ANSW" =~ ... ]] guard in BuildFixScript.
func emitRuleFixBlock(w io.Writer, id string) {
	switch id {

	// ---------------------------------------------------------------------
	// Crypto policy
	// ---------------------------------------------------------------------

	case "CIS-1.6.1":
		// Crypto policy not LEGACY / ensure modern policy
		fmt.Fprintln(w, `  echo " -> Setting system crypto policy to DEFAULT (non-LEGACY)..."`)
		fmt.Fprintln(w, "  if command -v update-crypto-policies >/dev/null 2>&1; then")
		fmt.Fprintln(w, "    update-crypto-policies --set DEFAULT || echo \"[WARN] update-crypto-policies failed\"")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] update-crypto-policies not found; configure crypto policy manually.\"")
		fmt.Fprintln(w, "  fi")

	// ---------------------------------------------------------------------
	// SSH hardening
	// ---------------------------------------------------------------------

	case "CIS-5.1.1":
		// Disable root login over SSH
		fmt.Fprintln(w, `  echo " -> Disabling root login over SSH..."`)
		fmt.Fprintln(w, "  if [ -f /etc/ssh/sshd_config ]; then")
		fmt.Fprintln(w, "    if grep -qE '^\\s*PermitRootLogin' /etc/ssh/sshd_config; then")
		fmt.Fprintln(w, "      sed -i 's/^\\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
		fmt.Fprintln(w, "    else")
		fmt.Fprintln(w, "      printf '\\nPermitRootLogin no\\n' >> /etc/ssh/sshd_config")
		fmt.Fprintln(w, "    fi")
		fmt.Fprintln(w, "    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] /etc/ssh/sshd_config not found; adjust SSH configuration manually.\"")
		fmt.Fprintln(w, "  fi")

	case "CIS-5.1.6":
		// X11Forwarding disabled
		fmt.Fprintln(w, `  echo " -> Disabling X11Forwarding in SSH..."`)
		fmt.Fprintln(w, "  if [ -f /etc/ssh/sshd_config ]; then")
		fmt.Fprintln(w, "    if grep -qE '^\\s*X11Forwarding' /etc/ssh/sshd_config; then")
		fmt.Fprintln(w, "      sed -i 's/^\\s*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config")
		fmt.Fprintln(w, "    else")
		fmt.Fprintln(w, "      printf '\\nX11Forwarding no\\n' >> /etc/ssh/sshd_config")
		fmt.Fprintln(w, "    fi")
		fmt.Fprintln(w, "    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] /etc/ssh/sshd_config not found; adjust SSH configuration manually.\"")
		fmt.Fprintln(w, "  fi")

	case "CIS-5.1.14":
		// SSH banner configured
		fmt.Fprintln(w, `  echo " -> Ensuring SSH banner is configured..."`)
		fmt.Fprintln(w, "  if [ ! -f /etc/issue.net ]; then")
		fmt.Fprintln(w, "    cat <<'EOF' >/etc/issue.net")
		fmt.Fprintln(w, "Authorized access only.")
		fmt.Fprintln(w, "Unauthorized use is prohibited.")
		fmt.Fprintln(w, "EOF")
		fmt.Fprintln(w, "  fi")
		fmt.Fprintln(w, "  if [ -f /etc/ssh/sshd_config ]; then")
		fmt.Fprintln(w, "    if grep -qE '^\\s*Banner' /etc/ssh/sshd_config; then")
		fmt.Fprintln(w, "      sed -i 's/^\\s*Banner.*/Banner \\/etc\\/issue.net/' /etc/ssh/sshd_config")
		fmt.Fprintln(w, "    else")
		fmt.Fprintln(w, "      printf '\\nBanner /etc/issue.net\\n' >> /etc/ssh/sshd_config")
		fmt.Fprintln(w, "    fi")
		fmt.Fprintln(w, "    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] /etc/ssh/sshd_config not found; adjust SSH configuration manually.\"")
		fmt.Fprintln(w, "  fi")

	// ---------------------------------------------------------------------
	// sudo hardening
	// ---------------------------------------------------------------------

	case "CIS-5.2.2":
		// sudo uses pty
		fmt.Fprintln(w, `  echo " -> Enforcing sudo use_pty via /etc/sudoers.d/redcheck-use-pty..."`)
		fmt.Fprintln(w, "  if [ -d /etc/sudoers.d ]; then")
		fmt.Fprintln(w, "    echo 'Defaults use_pty' > /etc/sudoers.d/redcheck-use-pty")
		fmt.Fprintln(w, "    chmod 440 /etc/sudoers.d/redcheck-use-pty")
		fmt.Fprintln(w, "    visudo -cf /etc/sudoers >/dev/null 2>&1 || echo \"[WARN] visudo reported an issue; review sudoers configuration.\"")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] /etc/sudoers.d not present; configure sudoers manually with visudo.\"")
		fmt.Fprintln(w, "  fi")

	case "CIS-5.2.3":
		// sudo has logfile
		fmt.Fprintln(w, `  echo " -> Enabling sudo logfile via /etc/sudoers.d/redcheck-sudo-log..."`)
		fmt.Fprintln(w, "  if [ -d /etc/sudoers.d ]; then")
		fmt.Fprintln(w, "    echo 'Defaults logfile=\"/var/log/sudo.log\"' > /etc/sudoers.d/redcheck-sudo-log")
		fmt.Fprintln(w, "    chmod 440 /etc/sudoers.d/redcheck-sudo-log")
		fmt.Fprintln(w, "    touch /var/log/sudo.log || true")
		fmt.Fprintln(w, "    visudo -cf /etc/sudoers >/dev/null 2>&1 || echo \"[WARN] visudo reported an issue; review sudoers configuration.\"")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] /etc/sudoers.d not present; configure sudoers manually with visudo.\"")
		fmt.Fprintln(w, "  fi")

	// ---------------------------------------------------------------------
	// Only root has UID 0  (HIGH RISK – guidance only)
	// ---------------------------------------------------------------------

	case "CIS-5.4.1":
		fmt.Fprintln(w, `  echo "[CAUTION] Fixing UID 0 accounts is HIGH RISK and requires manual review."`)
		fmt.Fprintln(w, `  echo "Listing accounts with UID 0 (excluding root):"`)
		fmt.Fprintln(w, `  awk -F: '($3 == 0 && $1 != "root"){print $1 ":" $3 ":" $7}' /etc/passwd || true`)
		fmt.Fprintln(w, `  echo "Review the above accounts and adjust with 'usermod' or 'vipw' manually."`)

	// ---------------------------------------------------------------------
	// Recon / PE rules
	// ---------------------------------------------------------------------

	case "RC-1.1":
		// Unexpected SUID/SGID files
		fmt.Fprintln(w, `  echo "[INFO] Listing non-standard SUID/SGID files for manual review..."`)
		fmt.Fprintln(w, "  find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | sort | tee /root/redcheck_suid_sgid.txt")
		fmt.Fprintln(w, `  echo "Review /root/redcheck_suid_sgid.txt and remove unsafe entries manually."`)

	case "RC-1.2":
		// World-writable dirs in PATH
		fmt.Fprintln(w, `  echo "[INFO] Listing world-writable directories in PATH for manual review..."`)
		fmt.Fprintln(w, "  echo \"$PATH\" | tr ':' '\\n' | while read -r d; do")
		fmt.Fprintln(w, "    [ -z \"$d\" ] && continue")
		fmt.Fprintln(w, "    if [ -d \"$d\" ] && [ -w \"$d\" ] && [ ! -O \"$d\" ]; then")
		fmt.Fprintln(w, "      ls -ld \"$d\"")
		fmt.Fprintln(w, "    fi")
		fmt.Fprintln(w, "  done")
		fmt.Fprintln(w, `  echo "Adjust permissions or remove unsafe PATH entries manually."`)

	// ---------------------------------------------------------------------
	// firewalld rules
	// ---------------------------------------------------------------------

	case "CIS-4.1.1":
		// firewalld installed
		fmt.Fprintln(w, `  echo " -> Installing firewalld using common package managers (dnf/yum/apt)..."`)
		fmt.Fprintln(w, "  if command -v dnf >/dev/null 2>&1; then")
		fmt.Fprintln(w, "    dnf install -y firewalld || echo \"[WARN] dnf install firewalld failed\"")
		fmt.Fprintln(w, "  elif command -v yum >/dev/null 2>&1; then")
		fmt.Fprintln(w, "    yum install -y firewalld || echo \"[WARN] yum install firewalld failed\"")
		fmt.Fprintln(w, "  elif command -v apt-get >/dev/null 2>&1; then")
		fmt.Fprintln(w, "    apt-get update && apt-get install -y firewalld || echo \"[WARN] apt-get install firewalld failed\"")
		fmt.Fprintln(w, "  else")
		fmt.Fprintln(w, "    echo \"[WARN] Unsupported package manager; install firewalld manually.\"")
		fmt.Fprintln(w, "  fi")

	case "CIS-4.1.2":
		// firewalld enabled and active
		fmt.Fprintln(w, `  echo " -> Enabling and starting firewalld..."`)
		fmt.Fprintln(w, "  systemctl enable --now firewalld || echo \"[WARN] Failed to enable/start firewalld; investigate manually.\"")

	// ---------------------------------------------------------------------
	// Default / unimplemented rules
	// ---------------------------------------------------------------------

	default:
		fmt.Fprintln(w, `  echo "[INFO] No automatic remediation implemented for this rule yet."`)
		fmt.Fprintln(w, `  echo "       Please follow the guidance from the redcheck report manually."`)
	}
}

