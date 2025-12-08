#!/usr/bin/env bash
set -euo pipefail

echo "[RedCheck] Auto-generated remediation script"
echo "[RedCheck] Review before running in production!"

# [CIS-1.1.2.2-devshm] /dev/shm mounted with nodev,nosuid,noexec
# TODO: automatic fix not implemented for this rule.
# Hint: Ensure /dev/shm has nodev,nosuid,noexec (fstab or systemd mount).

# [CIS-1.1.2.2-tmp] /tmp mounted with nodev,nosuid,noexec
# TODO: automatic fix not implemented for this rule.
# Hint: Ensure /tmp has nodev,nosuid,noexec (fstab or systemd tmp.mount).

# [CIS-1.6.1] Crypto policy not LEGACY
# TODO: automatic fix not implemented for this rule.
# Hint: Use `update-crypto-policies --set DEFAULT` (or higher), avoid LEGACY.

# [CIS-3.2.2] IPv4 redirects disabled (all)
# TODO: automatic fix not implemented for this rule.
# Hint: Set net.ipv4.conf.all.accept_redirects=0 and persist.

# [CIS-3.2.3] IPv4 redirects disabled (default)
# TODO: automatic fix not implemented for this rule.
# Hint: Set net.ipv4.conf.default.accept_redirects=0 and persist.

# [CIS-3.3.1] IPv6 redirects disabled (all)
# TODO: automatic fix not implemented for this rule.
# Hint: Set net.ipv6.conf.all.accept_redirects=0 and persist in sysctl.conf.

# [CIS-3.3.2] IPv6 redirects disabled (default)
# TODO: automatic fix not implemented for this rule.
# Hint: Set net.ipv6.conf.default.accept_redirects=0 and persist.

# [CIS-3.3.3] IPv6 accept_ra disabled (all)
# TODO: automatic fix not implemented for this rule.
# Hint: Set net.ipv6.conf.all.accept_ra=0 and persist.

# [CIS-3.3.4] IPv6 accept_ra disabled (default)
# TODO: automatic fix not implemented for this rule.
# Hint: Set net.ipv6.conf.default.accept_ra=0 and persist.

# [CIS-4.1.1] firewalld installed
echo "[RC] Installing firewalld..."
if command -v dnf >/dev/null 2>&1; then
  dnf install -y firewalld
elif command -v yum >/dev/null 2>&1; then
  yum install -y firewalld
else
  echo "[RC] No dnf/yum found; please install firewalld manually."
fi

# [CIS-4.1.2] firewalld enabled and active
echo "[RC] Enabling firewalld..."
systemctl enable --now firewalld

# [CIS-5.1.1] Disable root login over SSH
echo "[RC] Disabling root SSH login..."
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

# [CIS-5.1.14] SSH Banner configured
# TODO: automatic fix not implemented for this rule.
# Hint: Set 'Banner /etc/issue.net' (or similar) and reload sshd.

# [CIS-5.1.6] X11Forwarding disabled
# TODO: automatic fix not implemented for this rule.
# Hint: Set 'X11Forwarding no' in /etc/ssh/sshd_config and reload sshd.

# [CIS-5.2.3] sudo has logfile
echo "[RC] Enforcing sudo logfile..."
if [ -f /etc/sudoers ]; then
  grep -q 'Defaults logfile="/var/log/sudo.log"' /etc/sudoers || \
    echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
fi

# [CIS-5.3.1] PAM pwquality present
# TODO: automatic fix not implemented for this rule.
# Hint: Ensure pam_pwquality.so is configured in system-auth/password-auth (via authselect).

# [CIS-5.3.1-args] pwquality minlen >= 14
# TODO: automatic fix not implemented for this rule.
# Hint: Set minlen=14 in pam_pwquality.

# [CIS-5.3.1-minlen] pwquality minlen >= 14
# TODO: automatic fix not implemented for this rule.
# Hint: In pam_pwquality.so line(s), set minlen=14 or higher.

# [CIS-5.3.1-retry] pwquality retry <= 3
# TODO: automatic fix not implemented for this rule.
# Hint: In pam_pwquality.so line(s), set retry=3 or lower.

# [CIS-5.3.2] PAM pwhistory present
# TODO: automatic fix not implemented for this rule.
# Hint: Ensure pam_pwhistory.so is configured in system-auth/password-auth (via authselect).

# [CIS-5.3.2-remember] pwhistory remember >= 5
# TODO: automatic fix not implemented for this rule.
# Hint: In pam_pwhistory.so line(s), set remember=5 or higher.

# [CIS-5.3.3-fail-deny] faillock deny <= 5
# TODO: automatic fix not implemented for this rule.
# Hint: In pam_faillock.so line(s), set deny=5 or lower.

# [CIS-5.3.3-fail-unlock] faillock unlock_time >= 900
# TODO: automatic fix not implemented for this rule.
# Hint: In pam_faillock.so line(s), set unlock_time=900 or higher.

# [CIS-5.4.2] PASS_MAX_DAYS <= 365
# TODO: automatic fix not implemented for this rule.
# Hint: Set PASS_MAX_DAYS 365 (or lower) in /etc/login.defs.

# [CIS-5.4.3] PASS_MIN_DAYS >= 1
# TODO: automatic fix not implemented for this rule.
# Hint: Set PASS_MIN_DAYS 1 (or higher) in /etc/login.defs.

# [CIS-5.4.5] Default INACTIVE <= 30 days
# TODO: automatic fix not implemented for this rule.
# Hint: Set `useradd -D -f 30` to enforce default inactive lock.

# [CIS-5.4.users-aging] Local users comply with aging policy
# TODO: automatic fix not implemented for this rule.
# Hint: For each flagged user, adjust with 'chage' (MAX<=365, MIN>=1, INACTIVE<=30).

# [RC-1.1] Unexpected SUID/SGID files found
# TODO: automatic fix not implemented for this rule.
# Hint: Review SUID/SGID files and remove from non-standard locations.

