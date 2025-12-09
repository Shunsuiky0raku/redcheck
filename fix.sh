#!/bin/bash

set -e

echo "redcheck fix script (non-destructive helper)"
echo "Review and adapt each remediation before running on production systems."

echo "Fixing Crypto policy not LEGACY (CIS-1.6.1)"
# -------------------------------------------------------------------
# Rule ID    : CIS-1.6.1
# Title      : Crypto policy not LEGACY
# Category   : Auth
# Expected   : NOT_LEGACY
# Remediation steps (manual):
#   - Run: update-crypto-policies --set DEFAULT (or higher)
# TODO: Implement exact commands for your environment here.
# Example:
#   update-crypto-policies --set DEFAULT

echo "Fixing Disable root login over SSH (CIS-5.1.1)"
# -------------------------------------------------------------------
# Rule ID    : CIS-5.1.1
# Title      : Disable root login over SSH
# Category   : Auth
# Expected   : no
# Remediation steps (manual):
#   - Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.
# TODO: Implement exact commands for your environment here.
# Example:
#   nano /etc/ssh/sshd_config
#   # Apply the changes above, then:
#   systemctl reload sshd

echo "Fixing SSH Banner configured (CIS-5.1.14)"
# -------------------------------------------------------------------
# Rule ID    : CIS-5.1.14
# Title      : SSH Banner configured
# Category   : Auth
# Expected   : present
# Remediation steps (manual):
#   - Set 'Banner /etc/issue.net' or another approved file, then reload sshd.
# TODO: Implement exact commands for your environment here.
# Example:
#   nano /etc/ssh/sshd_config
#   # Apply the changes above, then:
#   systemctl reload sshd

echo "Fixing X11Forwarding disabled (CIS-5.1.6)"
# -------------------------------------------------------------------
# Rule ID    : CIS-5.1.6
# Title      : X11Forwarding disabled
# Category   : Auth
# Expected   : no
# Remediation steps (manual):
#   - Set 'X11Forwarding no' in /etc/ssh/sshd_config and reload sshd.
# TODO: Implement exact commands for your environment here.
# Example:
#   nano /etc/ssh/sshd_config
#   # Apply the changes above, then:
#   systemctl reload sshd

echo "Fixing sudo uses pty (CIS-5.2.2)"
# -------------------------------------------------------------------
# Rule ID    : CIS-5.2.2
# Title      : sudo uses pty
# Category   : Privileges
# Expected   : true
# Likely config location(s): /etc/sudoers, /etc/sudoers.d/
# Remediation steps (manual):
#   - Add 'Defaults use_pty' to /etc/sudoers.
# TODO: Implement exact commands for your environment here.
# Example:
#   visudo
#   # Add or adjust the Defaults line as described.

echo "Fixing sudo has logfile (CIS-5.2.3)"
# -------------------------------------------------------------------
# Rule ID    : CIS-5.2.3
# Title      : sudo has logfile
# Category   : Privileges
# Expected   : true
# Likely config location(s): /etc/sudoers, /etc/sudoers.d/
# Remediation steps (manual):
#   - Add 'Defaults logfile="/var/log/sudo.log"' to /etc/sudoers.
# TODO: Implement exact commands for your environment here.
# Example:
#   visudo
#   # Add or adjust the Defaults line as described.

echo "Fixing Only root has UID 0 (CIS-5.4.1)"
# -------------------------------------------------------------------
# Rule ID    : CIS-5.4.1
# Title      : Only root has UID 0
# Category   : Privileges
# Expected   : true
# Likely config location(s): /etc/login.defs, chage(1) per-user settings
# Remediation steps (manual):
#   - Remove UID 0 from non-root accounts.
# TODO: Implement exact commands for your environment here.
# Example:
#   # Apply the steps above based on your distro.

echo "Fixing World-writable directories in PATH (RC-1.2)"
# -------------------------------------------------------------------
# Rule ID    : RC-1.2
# Title      : World-writable directories in PATH
# Category   : Privileges
# Expected   : none
# Likely config location(s): Use: find(1), ls(1), and manual review of SUID/SGID binaries and $PATH dirs
# Remediation steps (manual):
#   - Remove world-writable permissions from directories in PATH.
# TODO: Implement exact commands for your environment here.
# Example:
#   # Apply the steps above based on your distro.

echo "Fixing Unexpected SUID/SGID files found (RC-1.1)"
# -------------------------------------------------------------------
# Rule ID    : RC-1.1
# Title      : Unexpected SUID/SGID files found
# Category   : Recon
# Expected   : none
# Likely config location(s): Use: find(1), ls(1), and manual review of SUID/SGID binaries and $PATH dirs
# Remediation steps (manual):
#   - Remove unnecessary SUID/SGID files.
# TODO: Implement exact commands for your environment here.
# Example:
#   # Apply the steps above based on your distro.

echo "Fixing firewalld installed (CIS-4.1.1)"
# -------------------------------------------------------------------
# Rule ID    : CIS-4.1.1
# Title      : firewalld installed
# Category   : Services
# Expected   : present
# Likely config location(s): /etc/sysctl.conf, /etc/sysctl.d/*.conf, /usr/lib/sysctl.d/*.conf
# Remediation steps (manual):
#   - Install firewalld using your package manager and enable the service.
# TODO: Implement exact commands for your environment here.
# Example:
#   dnf install -y firewalld
#   systemctl enable --now firewalld

echo "Fixing firewalld enabled and active (CIS-4.1.2)"
# -------------------------------------------------------------------
# Rule ID    : CIS-4.1.2
# Title      : firewalld enabled and active
# Category   : Services
# Expected   : enabled_active
# Likely config location(s): /etc/sysctl.conf, /etc/sysctl.d/*.conf, /usr/lib/sysctl.d/*.conf
# Remediation steps (manual):
#   - Run: systemctl enable --now firewalld
# TODO: Implement exact commands for your environment here.
# Example:
#   dnf install -y firewalld
#   systemctl enable --now firewalld

echo "All suggested remediations have been listed above."
echo "Review this script and convert comments into real commands where appropriate."
