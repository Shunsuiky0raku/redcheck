package checks

import (
	"bufio"
	"os"
	"strings"
)

func UID0Unique() (string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "unknown", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[2] == "0" {
			count++
		}
	}
	if count == 1 {
		return "true", nil
	}
	return "false", nil
}
