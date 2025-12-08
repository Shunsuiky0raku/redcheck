#!/bin/bash

set -e

echo "Fixing Crypto policy not LEGACY (CIS-1.6.1)"
# Remediation:
# Run: update-crypto-policies --set DEFAULT (or higher)

echo "Fixing sudo has logfile (CIS-5.2.3)"
# Remediation:
# Add 'Defaults logfile="/var/log/sudo.log"' to /etc/sudoers.

echo "Fixing X11Forwarding disabled (CIS-5.1.6)"
# Remediation:
# Set 'X11Forwarding no' in /etc/ssh/sshd_config and reload sshd.

echo "Fixing SSH Banner configured (CIS-5.1.14)"
# Remediation:
# Set 'Banner /etc/issue.net' or another approved file, then reload sshd.

echo "Fixing Disable root login over SSH (CIS-5.1.1)"
# Remediation:
# Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.

echo "Fixing firewalld installed (CIS-4.1.1)"
# Remediation:
# Install firewalld using your package manager and enable the service.

echo "Fixing firewalld enabled and active (CIS-4.1.2)"
# Remediation:
# Run: systemctl enable --now firewalld

echo "Fixing sudo uses pty (CIS-5.2.2)"
# Remediation:
# Add 'Defaults use_pty' to /etc/sudoers.

echo "Fixing Unexpected SUID/SGID files found (RC-1.1)"
# Remediation:
# Remove unnecessary SUID/SGID files.

echo "Fixing World-writable directories in PATH (RC-1.2)"
# Remediation:
# Remove world-writable permissions from directories in PATH.

echo "Fixing Only root has UID 0 (CIS-5.4.1)"
# Remediation:
# Remove UID 0 from non-root accounts.

