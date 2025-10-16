package checks

import (
	"os"
	"strings"
)

func pamFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ToLower(string(b))
}

func pamAny(paths []string) string {
	var all strings.Builder
	for _, p := range paths {
		all.WriteString(pamFile(p))
		all.WriteByte('\n')
	}
	return all.String()
}

func PamPwqualityPresent() (string, error) {
	s := pamAny([]string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"})
	if strings.Contains(s, "pam_pwquality.so") {
		return "true", nil
	}
	return "false", nil
}

func PamPwhistoryPresent() (string, error) {
	s := pamAny([]string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"})
	if strings.Contains(s, "pam_pwhistory.so") {
		return "true", nil
	}
	return "false", nil
}

func PamFaillockPresent() (string, error) {
	s := pamAny([]string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"})
	if strings.Contains(s, "pam_faillock.so") {
		return "true", nil
	}
	return "false", nil
}
