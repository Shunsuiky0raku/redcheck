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

// tiny helper for includes (future):
func resolveIncludes(dir, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	return matches, err
}
