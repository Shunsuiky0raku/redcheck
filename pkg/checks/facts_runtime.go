package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// gatherFactsForRule is the dynamic fact engine.
// For now it's fact-centric: it looks at rule.Fact and collects just what is needed
// for that rule. This keeps it simple and fast for your current rule set.
func gatherFactsForRule(rule Rule, timeout time.Duration) (map[string]string, string) {
	facts := make(map[string]string)

	if rule.Fact == "" {
		return facts, ""
	}

	var observed, evidence string

	switch rule.Fact {
	// ── SSH FACTS ──────────────────────────────────────────────────────────────
	case "ssh.permit_root_login":
		observed, evidence = factSSHPermitRootLogin()
	case "ssh.x11_forwarding":
		observed, evidence = factSSHX11Forwarding()
	case "ssh.banner":
		observed, evidence = factSSHBanner()

	// ── MOUNT OPTIONS (FS_PERMS) ──────────────────────────────────────────────
	case "mount.devshm_options":
		observed, evidence = factMountOptions("/dev/shm")
	case "mount.tmp_options":
		observed, evidence = factMountOptions("/tmp")
	case "mount.vartmp_options":
		observed, evidence = factMountOptions("/var/tmp")

	// ── FIREWALL / SERVICES ───────────────────────────────────────────────────
	case "pkg.firewalld_installed":
		observed, evidence = factPkgFirewalldInstalled()
	case "svc.firewalld_state":
		observed, evidence = factSvcFirewalldState(timeout)
	case "svc.sshd_state":
		observed, evidence = factSvcSSHState(timeout)

	// ── CRYPTO POLICY ─────────────────────────────────────────────────────────
	case "crypto.policy":
		observed, evidence = factCryptoPolicy()

	// ── SUDO ──────────────────────────────────────────────────────────────────
	case "sudo.use_pty":
		observed, evidence = factSudoUsePTY()
	case "sudo.logfile":
		observed, evidence = factSudoLogfile()

	// ── ACCOUNTS / PRIVILEGES ─────────────────────────────────────────────────
	case "acct.uid0_unique":
		observed, evidence = factAcctUID0Unique()

	// ── RECON / PRIVESC ───────────────────────────────────────────────────────
	case "recon.suid_sgid_unexpected":
		observed, evidence = factReconSuidSgidUnexpected()
	case "recon.path_world_writable":
		observed, evidence = factReconWorldWritablePath()

	default:
		// Unknown fact: leave observed empty but record a hint in evidence when verbose.
		evidence = fmt.Sprintf("no collector implemented for fact %q", rule.Fact)
	}

	facts[rule.Fact] = observed
	return facts, evidence
}

//
// ───────────────────────────────── SSH HELPERS ──────────────────────────────
//

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func findDirective(lines []string, key string) (string, bool) {
	keyLower := strings.ToLower(key)
	var val string
	found := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if strings.ToLower(parts[0]) == keyLower {
			val = parts[1]
			found = true
			// last one wins, mirroring sshd behaviour
		}
	}
	return val, found
}

func factSSHPermitRootLogin() (string, string) {
	lines, err := readLines("/etc/ssh/sshd_config")
	if err != nil {
		return "", fmt.Sprintf("read /etc/ssh/sshd_config: %v", err)
	}
	val, ok := findDirective(lines, "PermitRootLogin")
	if !ok {
		return "", "PermitRootLogin not set explicitly; relying on sshd default"
	}
	valLower := strings.ToLower(val)
	return valLower, fmt.Sprintf("PermitRootLogin %s", valLower)
}

func factSSHX11Forwarding() (string, string) {
	lines, err := readLines("/etc/ssh/sshd_config")
	if err != nil {
		return "", fmt.Sprintf("read /etc/ssh/sshd_config: %v", err)
	}
	val, ok := findDirective(lines, "X11Forwarding")
	if !ok {
		return "", "X11Forwarding not set explicitly; relying on sshd default"
	}
	valLower := strings.ToLower(val)
	return valLower, fmt.Sprintf("X11Forwarding %s", valLower)
}

func factSSHBanner() (string, string) {
	lines, err := readLines("/etc/ssh/sshd_config")
	if err != nil {
		return "", fmt.Sprintf("read /etc/ssh/sshd_config: %v", err)
	}
	val, ok := findDirective(lines, "Banner")
	if !ok {
		return "absent", "no Banner directive in sshd_config"
	}
	if strings.EqualFold(val, "none") {
		return "absent", "Banner is explicitly set to none"
	}
	if _, err := os.Stat(val); err == nil {
		return "present", fmt.Sprintf("Banner %s exists", val)
	}
	return "absent", fmt.Sprintf("Banner %s configured but file missing", val)
}

//
// ─────────────────────────────── MOUNT OPTIONS ──────────────────────────────
//

func factMountOptions(target string) (string, string) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Sprintf("read /proc/mounts: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mountPoint := fields[1]
		opts := fields[3]
		if mountPoint == target {
			return opts, fmt.Sprintf("from /proc/mounts: %s", line)
		}
	}
	return "", fmt.Sprintf("mount point %s not found in /proc/mounts", target)
}

//
// ─────────────────────────────── SERVICES / FIREWALL ───────────────────────
//

func factPkgFirewalldInstalled() (string, string) {
	paths := []string{
		"/usr/lib/systemd/system/firewalld.service",
		"/lib/systemd/system/firewalld.service",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return "present", fmt.Sprintf("found firewalld service unit at %s", p)
		}
	}
	return "absent", "firewalld service unit not found"
}

func runCommand(timeout time.Duration, name string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	out := strings.TrimSpace(outBuf.String())
	errOut := strings.TrimSpace(errBuf.String())
	return out, errOut, err
}

func factSvcFirewalldState(timeout time.Duration) (string, string) {
	enabled, errOut1, err1 := runCommand(timeout, "systemctl", "is-enabled", "firewalld")
	active, errOut2, err2 := runCommand(timeout, "systemctl", "is-active", "firewalld")

	if err1 != nil && err2 != nil {
		return "", fmt.Sprintf("systemctl is-enabled/is-active firewalld failed: %v / %v (stderr: %s / %s)", err1, err2, errOut1, errOut2)
	}

	enabled = strings.TrimSpace(enabled)
	active = strings.TrimSpace(active)

	if enabled == "enabled" && active == "active" {
		return "enabled_active", fmt.Sprintf("firewalld is-enabled=%s, is-active=%s", enabled, active)
	}

	state := fmt.Sprintf("%s_%s", enabled, active)
	return state, fmt.Sprintf("firewalld is-enabled=%s, is-active=%s", enabled, active)
}

func factSvcSSHState(timeout time.Duration) (string, string) {
	active, errOut, err := runCommand(timeout, "systemctl", "is-active", "sshd")
	if err != nil {
		return "", fmt.Sprintf("systemctl is-active sshd failed: %v (stderr: %s)", err, errOut)
	}
	active = strings.TrimSpace(active)
	return active, fmt.Sprintf("sshd is-active=%s", active)
}

//
// ─────────────────────────────── CRYPTO POLICY ──────────────────────────────
//

func factCryptoPolicy() (string, string) {
	data, err := os.ReadFile("/etc/crypto-policies/config")
	if err != nil {
		return "", fmt.Sprintf("read /etc/crypto-policies/config: %v", err)
	}
	policy := strings.TrimSpace(string(data))
	if strings.EqualFold(policy, "LEGACY") {
		return "LEGACY", fmt.Sprintf("crypto policy = %s", policy)
	}
	return "NOT_LEGACY", fmt.Sprintf("crypto policy = %s", policy)
}

//
// ───────────────────────────────────── SUDO ─────────────────────────────────
//

func readSudoConfigLines() ([]string, error) {
	var paths []string
	paths = append(paths, "/etc/sudoers")

	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, filepath.Join("/etc/sudoers.d", e.Name()))
			}
		}
	}

	var all []string
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			all = append(all, scanner.Text())
		}
		_ = f.Close()
	}
	return all, nil
}

func factSudoUsePTY() (string, string) {
	lines, err := readSudoConfigLines()
	if err != nil {
		return "", fmt.Sprintf("read sudo config: %v", err)
	}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "Defaults") && strings.Contains(trim, "use_pty") {
			return "true", fmt.Sprintf("matched: %s", trim)
		}
	}
	return "false", "no 'Defaults use_pty' found in sudoers or sudoers.d"
}

func factSudoLogfile() (string, string) {
	lines, err := readSudoConfigLines()
	if err != nil {
		return "", fmt.Sprintf("read sudo config: %v", err)
	}
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "Defaults") && strings.Contains(trim, "logfile=") {
			return "true", fmt.Sprintf("matched: %s", trim)
		}
	}
	return "false", "no 'Defaults logfile=…' found in sudoers or sudoers.d"
}

//
// ───────────────────────────── ACCOUNTS / PRIVILEGES ───────────────────────
//

func factAcctUID0Unique() (string, string) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", fmt.Sprintf("read /etc/passwd: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	var uid0Users []string
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if parts[2] == "0" {
			uid0Users = append(uid0Users, parts[0])
		}
	}

	if len(uid0Users) == 1 && uid0Users[0] == "root" {
		return "true", "only UID 0 account is root"
	}
	if len(uid0Users) == 0 {
		// Extremely weird, but let's be explicit
		return "false", "no UID 0 accounts found in /etc/passwd"
	}
	return "false", fmt.Sprintf("UID 0 accounts: %s", strings.Join(uid0Users, ", "))
}

//
// ─────────────────────────────── RECON / PRIVESC ───────────────────────────
//

// For your lab, we keep this intentionally scoped to /opt/redcheck-ww
// to avoid a super-heavy full-disk find() on every run.
func factReconSuidSgidUnexpected() (string, string) {
	root := "/opt/redcheck-ww"

	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "none", "no /opt/redcheck-ww directory (nothing to check)"
	}

	var hits []string

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()
		// Check for SUID / SGID bits
		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			hits = append(hits, path)
		}
		return nil
	})

	if len(hits) == 0 {
		return "none", "no SUID/SGID files found under /opt/redcheck-ww"
	}

	return strings.Join(hits, ","), "unexpected SUID/SGID files: " + strings.Join(hits, ", ")
}

func factReconWorldWritablePath() (string, string) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "none", "PATH is empty"
	}

	dirs := filepath.SplitList(pathEnv)
	var ww []string

	for _, d := range dirs {
		if d == "" {
			continue
		}
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0o002 != 0 { // world-writable bit
			ww = append(ww, d)
		}
	}

	if len(ww) == 0 {
		return "none", "no world-writable directories in PATH"
	}
	return strings.Join(ww, ":"), "world-writable PATH dirs: " + strings.Join(ww, ", ")
}

//
// ────────────────────────────── SMALL STRING HELPERS ───────────────────────
//

func evaluateAllOf(observed string, expectedAll []string) []string {
	var missing []string
	for _, want := range expectedAll {
		if !strings.Contains(observed, want) {
			missing = append(missing, want)
		}
	}
	return missing
}

func joinExpected(expectedAll []string) string {
	return strings.Join(expectedAll, ",")
}
