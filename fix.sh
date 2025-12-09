#!/bin/bash

set -e

echo "redcheck semi-automatic fix script"
echo "You will be prompted before each change."
echo "Review this script before running it on production systems."


echo
echo "============================================================"
echo "Rule     : Only root has UID 0 (CIS-5.4.1)"
echo "Category : Privileges"
echo "Expected : true"
echo "Remediation (summary): Remove UID 0 from non-root accounts."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo "[CAUTION] Fixing UID 0 accounts is HIGH RISK and requires manual review."
  echo "Listing accounts with UID 0 (excluding root):"
  awk -F: '($3 == 0 && $1 != "root"){print $1 ":" $3 ":" $7}' /etc/passwd || true
  echo "Review the above accounts and adjust with 'usermod' or 'vipw' manually."
else
  echo "[SKIP] Skipped fix for CIS-5.4.1"
fi

echo
echo "============================================================"
echo "Rule     : firewalld installed (CIS-4.1.1)"
echo "Category : Services"
echo "Expected : present"
echo "Remediation (summary): Install firewalld using your package manager and enable the service."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Installing firewalld using common package managers (dnf/yum/apt)..."
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y firewalld || echo "[WARN] dnf install firewalld failed"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y firewalld || echo "[WARN] yum install firewalld failed"
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y firewalld || echo "[WARN] apt-get install firewalld failed"
  else
    echo "[WARN] Unsupported package manager; install firewalld manually."
  fi
else
  echo "[SKIP] Skipped fix for CIS-4.1.1"
fi

echo
echo "============================================================"
echo "Rule     : firewalld enabled and active (CIS-4.1.2)"
echo "Category : Services"
echo "Expected : enabled_active"
echo "Remediation (summary): Run: systemctl enable --now firewalld"
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Enabling and starting firewalld..."
  systemctl enable --now firewalld || echo "[WARN] Failed to enable/start firewalld; investigate manually."
else
  echo "[SKIP] Skipped fix for CIS-4.1.2"
fi

echo
echo "============================================================"
echo "Rule     : Disable root login over SSH (CIS-5.1.1)"
echo "Category : Auth"
echo "Expected : no"
echo "Remediation (summary): Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Disabling root login over SSH..."
  if [ -f /etc/ssh/sshd_config ]; then
    if grep -qE '^\s*PermitRootLogin' /etc/ssh/sshd_config; then
      sed -i 's/^\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
      printf '\nPermitRootLogin no\n' >> /etc/ssh/sshd_config
    fi
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  else
    echo "[WARN] /etc/ssh/sshd_config not found; adjust SSH configuration manually."
  fi
else
  echo "[SKIP] Skipped fix for CIS-5.1.1"
fi

echo
echo "============================================================"
echo "Rule     : sudo uses pty (CIS-5.2.2)"
echo "Category : Privileges"
echo "Expected : true"
echo "Remediation (summary): Add 'Defaults use_pty' to /etc/sudoers."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Enforcing sudo use_pty via /etc/sudoers.d/redcheck-use-pty..."
  if [ -d /etc/sudoers.d ]; then
    echo 'Defaults use_pty' > /etc/sudoers.d/redcheck-use-pty
    chmod 440 /etc/sudoers.d/redcheck-use-pty
    visudo -cf /etc/sudoers >/dev/null 2>&1 || echo "[WARN] visudo reported an issue; review sudoers configuration."
  else
    echo "[WARN] /etc/sudoers.d not present; configure sudoers manually with visudo."
  fi
else
  echo "[SKIP] Skipped fix for CIS-5.2.2"
fi

echo
echo "============================================================"
echo "Rule     : Unexpected SUID/SGID files found (RC-1.1)"
echo "Category : Recon"
echo "Expected : none"
echo "Remediation (summary): Remove unnecessary SUID/SGID files."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo "[INFO] Listing non-standard SUID/SGID files for manual review..."
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort | tee /root/redcheck_suid_sgid.txt
  echo "Review /root/redcheck_suid_sgid.txt and remove unsafe entries manually."
else
  echo "[SKIP] Skipped fix for RC-1.1"
fi

echo
echo "============================================================"
echo "Rule     : World-writable directories in PATH (RC-1.2)"
echo "Category : Privileges"
echo "Expected : none"
echo "Remediation (summary): Remove world-writable permissions from directories in PATH."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo "[INFO] Listing world-writable directories in PATH for manual review..."
  echo "$PATH" | tr ':' '\n' | while read -r d; do
    [ -z "$d" ] && continue
    if [ -d "$d" ] && [ -w "$d" ] && [ ! -O "$d" ]; then
      ls -ld "$d"
    fi
  done
  echo "Adjust permissions or remove unsafe PATH entries manually."
else
  echo "[SKIP] Skipped fix for RC-1.2"
fi

echo
echo "============================================================"
echo "Rule     : Crypto policy not LEGACY (CIS-1.6.1)"
echo "Category : Auth"
echo "Expected : NOT_LEGACY"
echo "Remediation (summary): Run: update-crypto-policies --set DEFAULT (or higher)"
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Setting system crypto policy to DEFAULT (non-LEGACY)..."
  if command -v update-crypto-policies >/dev/null 2>&1; then
    update-crypto-policies --set DEFAULT || echo "[WARN] update-crypto-policies failed"
  else
    echo "[WARN] update-crypto-policies not found; configure crypto policy manually."
  fi
else
  echo "[SKIP] Skipped fix for CIS-1.6.1"
fi

echo
echo "============================================================"
echo "Rule     : sudo has logfile (CIS-5.2.3)"
echo "Category : Privileges"
echo "Expected : true"
echo "Remediation (summary): Add 'Defaults logfile=\"/var/log/sudo.log\"' to /etc/sudoers."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Enabling sudo logfile via /etc/sudoers.d/redcheck-sudo-log..."
  if [ -d /etc/sudoers.d ]; then
    echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/redcheck-sudo-log
    chmod 440 /etc/sudoers.d/redcheck-sudo-log
    touch /var/log/sudo.log || true
    visudo -cf /etc/sudoers >/dev/null 2>&1 || echo "[WARN] visudo reported an issue; review sudoers configuration."
  else
    echo "[WARN] /etc/sudoers.d not present; configure sudoers manually with visudo."
  fi
else
  echo "[SKIP] Skipped fix for CIS-5.2.3"
fi

echo
echo "============================================================"
echo "Rule     : SSH Banner configured (CIS-5.1.14)"
echo "Category : Auth"
echo "Expected : present"
echo "Remediation (summary): Set 'Banner /etc/issue.net' or another approved file, then reload sshd."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Ensuring SSH banner is configured..."
  if [ ! -f /etc/issue.net ]; then
    cat <<'EOF' >/etc/issue.net
Authorized access only.
Unauthorized use is prohibited.
EOF
  fi
  if [ -f /etc/ssh/sshd_config ]; then
    if grep -qE '^\s*Banner' /etc/ssh/sshd_config; then
      sed -i 's/^\s*Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    else
      printf '\nBanner /etc/issue.net\n' >> /etc/ssh/sshd_config
    fi
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  else
    echo "[WARN] /etc/ssh/sshd_config not found; adjust SSH configuration manually."
  fi
else
  echo "[SKIP] Skipped fix for CIS-5.1.14"
fi

echo
echo "============================================================"
echo "Rule     : X11Forwarding disabled (CIS-5.1.6)"
echo "Category : Auth"
echo "Expected : no"
echo "Remediation (summary): Set 'X11Forwarding no' in /etc/ssh/sshd_config and reload sshd."
read -r -p "Apply this remediation? [y/N]: " ANSW
if [[ "$ANSW" =~ ^[Yy]$ ]]; then
  echo " -> Disabling X11Forwarding in SSH..."
  if [ -f /etc/ssh/sshd_config ]; then
    if grep -qE '^\s*X11Forwarding' /etc/ssh/sshd_config; then
      sed -i 's/^\s*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    else
      printf '\nX11Forwarding no\n' >> /etc/ssh/sshd_config
    fi
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  else
    echo "[WARN] /etc/ssh/sshd_config not found; adjust SSH configuration manually."
  fi
else
  echo "[SKIP] Skipped fix for CIS-5.1.6"
fi

echo "All interactive fixes processed."
echo "Re-run: sudo ./redcheck scan --all to verify the new posture."
