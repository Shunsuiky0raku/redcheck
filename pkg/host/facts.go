package host

import (
	"os"
	"strings"
)

type Facts map[string]string

// readFile trims and returns file content (best-effort).
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}
