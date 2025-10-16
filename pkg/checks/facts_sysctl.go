package checks

import (
	"os/exec"
	"strings"
)

func SysctlValue(key string) (string, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	return strings.TrimSpace(string(out)), err
}
