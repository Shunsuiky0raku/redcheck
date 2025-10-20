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

// Very simple arg finders; we can harden later.
func PamPwqualityArgs() map[string]string {
	s := pamAny([]string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"})
	return parsePamArgs(s, "pam_pwquality.so")
}
func PamPwhistoryArgs() map[string]string {
	s := pamAny([]string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"})
	return parsePamArgs(s, "pam_pwhistory.so")
}
func PamFaillockArgs() map[string]string {
	s := pamAny([]string{"/etc/pam.d/system-auth", "/etc/pam.d/password-auth"})
	return parsePamArgs(s, "pam_faillock.so")
}
func parsePamArgs(all, module string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(all, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || !strings.Contains(l, module) {
			continue
		}
		for _, tok := range strings.Fields(l) {
			if !strings.Contains(tok, "=") {
				continue
			}
			kv := strings.SplitN(tok, "=", 2)
			out[strings.ToLower(kv[0])] = kv[1]
		}
	}
	return out
}
