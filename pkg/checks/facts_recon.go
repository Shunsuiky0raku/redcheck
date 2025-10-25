package checks

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// findSuidSgid scans common paths for files with SUID/SGID bits.
// We ignore some expected safe locations.
func ReconSuidSgidUnexpected() (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("find", "/", "-xdev",
		"(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
		"-type", "f", "-printf", "%p\n")
	cmd.Stdout = &out
	cmd.Stderr = nil
	_ = cmd.Run() // best-effort
	lines := strings.Split(out.String(), "\n")

	ignorePrefixes := []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"}
	var unexpected []string
	for _, p := range lines {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		skip := false
		for _, prefix := range ignorePrefixes {
			if strings.HasPrefix(p, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			unexpected = append(unexpected, p)
		}
	}

	if len(unexpected) == 0 {
		return "none", nil
	}
	return strings.Join(unexpected, ","), nil
}

// pathWorldWritable checks for any world-writable dirs in $PATH
func ReconPathWorldWritable() (string, error) {
	env := os.Getenv("PATH")
	paths := strings.Split(env, ":")
	var bad []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0o002 != 0 { // world writable
			bad = append(bad, filepath.Clean(p))
		}
	}
	if len(bad) == 0 {
		return "none", nil
	}
	return strings.Join(bad, ","), nil
}
