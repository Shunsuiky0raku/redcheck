package checks

import (
	"bufio"
	"os"
	"strings"
)

func grepFirstLineInFile(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.Contains(line, key) {
			return line
		}
	}
	return ""
}
