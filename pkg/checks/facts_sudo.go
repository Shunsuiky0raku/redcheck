package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func sudoersContent() string {
	paths := []string{"/etc/sudoers"}
	dir := "/etc/sudoers.d"
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	var b strings.Builder
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			b.Write(data)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// "Defaults timestamp_timeout=15" -> sane if <=15 (or unset == default 5)
func SudoTimestampTimeoutSane() (string, error) {
	s := sudoersContent()
	re := regexp.MustCompile(`(?i)^\s*Defaults\s+.*timestamp_timeout\s*=\s*(-?\d+)\b`)
	m := re.FindStringSubmatch(s)
	if len(m) == 0 {
		// treat "unset" as sane (CIS allows small default)
		return "true", nil
	}
	v, err := strconv.Atoi(m[1])
	if err != nil {
		return "false", nil
	}
	if v <= 15 {
		return "true", nil
	}
	return "false", nil
}

// Forbid any "NOPASSWD: ALL" (or wildcards) on Cmnd_Alias or ALL
func SudoNoPasswdWildcardForbidden() (string, error) {
	s := sudoersContent()
	// very simple heuristic: if NOPASSWD and ALL appear on same line, we consider it forbidden
	lines := strings.Split(s, "\n")
	for _, ln := range lines {
		l := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		if strings.Contains(l, "nopasswd") && (strings.Contains(l, " ALL") || strings.Contains(l, " all")) {
			return "false", nil
		}
	}
	return "true", nil
}

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
