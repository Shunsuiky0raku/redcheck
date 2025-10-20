package checks

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// returns ("true"/"false" or "unknown"), observed: "user1[max=...;min=...;inactive=...], user2[...]"
func AccountsAgingPolicyOK() (string, string, error) {
	users := localHumanUsers()
	var offenders []string

	for _, u := range users {
		max, min, inactive, err := chageInfo(u)
		if err != nil {
			// if chage not present or error, report unknown once
			return "unknown", "chage_error", err
		}
		// Policy: MAX<=365, MIN>=1, INACTIVE<=30 (or -1 == never -> treat as violation)
		if (max <= 0 || max > 365) || (min < 1) || (inactive < 0 || inactive > 30) {
			offenders = append(offenders, u+"[max="+itoa(max)+";min="+itoa(min)+";inactive="+itoa(inactive)+"]")
		}
	}

	if len(offenders) == 0 {
		return "true", "", nil
	}
	return "false", strings.Join(offenders, ", "), nil
}

func localHumanUsers() []string {
	// UID >=1000 and shell not nologin/false
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		shell := parts[6]
		if uid >= 1000 && !strings.Contains(shell, "nologin") && !strings.HasSuffix(shell, "/false") {
			out = append(out, parts[0])
		}
	}
	return out
}

func chageInfo(user string) (max, min, inactive int, err error) {
	cmd := exec.Command("chage", "-l", user)
	b, e := cmd.Output()
	if e != nil {
		return 0, 0, 0, e
	}
	// parse lines like:
	// "Maximum number of days between password change : 365"
	// "Minimum number of days between password change : 1"
	// "Number of days of inactivity before account is locked : 30"
	s := string(b)
	max = findIntAfter(s, "Maximum number of days between password change")
	min = findIntAfter(s, "Minimum number of days between password change")
	inactive = findIntAfter(s, "Number of days of inactivity before account is locked")
	return
}

func findIntAfter(s, prefix string) int {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			// take last token
			fs := strings.Fields(line)
			if len(fs) > 0 {
				if n, err := strconv.Atoi(fs[len(fs)-1]); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

func itoa(n int) string { return strconv.Itoa(n) }
