package checks

import (
	"os"
	"path/filepath"
	"strings"
)

func readSudoers() string {
	paths := []string{"/etc/sudoers"}
	dir := "/etc/sudoers.d"
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	var all strings.Builder
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			all.Write(b)
			all.WriteByte('\n')
		}
	}
	return all.String()
}

func SudoUsePTY() (string, error) {
	s := readSudoers()
	if strings.Contains(s, "Defaults") && strings.Contains(s, "use_pty") {
		return "true", nil
	}
	return "false", nil
}

func SudoLogfile() (string, error) {
	s := readSudoers()
	if strings.Contains(s, "Defaults") && strings.Contains(s, "logfile=") {
		return "true", nil
	}
	return "false", nil
}
