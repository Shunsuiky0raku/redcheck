package checks

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func SSHPermitRootLogin() (string, error) {
	// minimal: read /etc/ssh/sshd_config (we’ll add “Include” handling later)
	f := "/etc/ssh/sshd_config"
	b, err := os.ReadFile(f)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	val := "default" // if not set, CIS treats as not allowed; we’ll map later
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "PermitRootLogin") {
			return strings.ToLower(fields[1]), nil
		}
	}
	return val, nil
}

// tiny helper for includes (future):
func resolveIncludes(dir, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	return matches, err
}
