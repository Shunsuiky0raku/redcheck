package checks

import (
	"os/exec"
	"strings"
)

func MountOptions(target string) (string, error) {
	out, err := exec.Command("findmnt", target, "-no", "OPTIONS").Output()
	return strings.TrimSpace(string(out)), err
}
