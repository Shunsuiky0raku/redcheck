package checks

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

func SSHPermitRootLogin() (string, error) {
	paths := []string{"/etc/ssh/sshd_config"}
	// naive include support: Include /etc/ssh/sshd_config.d/*.conf
	// (We’ll expand later if needed)
	dir := "/etc/ssh/sshd_config.d"
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	val := "default"
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 && strings.EqualFold(f[0], "PermitRootLogin") {
				val = strings.ToLower(f[1])
			}
		}
	}
	return val, nil
}
func SSHX11Forwarding() (string, error) {
	val := "default"
	for _, p := range sshdPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 && strings.EqualFold(f[0], "X11Forwarding") {
				val = strings.ToLower(f[1])
			}
		}
	}
	return val, nil
}

func SSHBannerPresent() (string, error) {
	found := false
	for _, p := range sshdPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 && strings.EqualFold(f[0], "Banner") {
				found = true
			}
		}
	}
	if found {
		return "present", nil
	}
	return "absent", nil
}

func sshdPaths() []string {
	paths := []string{"/etc/ssh/sshd_config"}
	dir := "/etc/ssh/sshd_config.d"
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	return paths
}

// tiny helper for includes (future):
func resolveIncludes(dir, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	return matches, err
}
func SSHRootLoginDisabled() (val, evidence string, err error) {
	b, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "unknown", "", err
	}
	s := string(b)
	// capture the line
	line := grepFirstLine(s, "PermitRootLogin")
	if strings.Contains(line, "no") {
		return "true", "PermitRootLogin line: " + strings.TrimSpace(line), nil
	}
	return "false", "PermitRootLogin line: " + strings.TrimSpace(line), nil
}
func grepFirstLine(s, key string) string {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, key) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return line
		}
	}
	return ""
}
