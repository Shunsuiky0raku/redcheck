package checks

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func readLoginDefs() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/etc/login.defs")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) >= 2 {
			k := strings.ToUpper(fs[0])
			v := fs[1]
			out[k] = v
		}
	}
	return out
}

func LoginDefsPassMaxDaysOK() (string, error) {
	m := readLoginDefs()
	v, ok := m["PASS_MAX_DAYS"]
	if !ok {
		return "false", nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return "false", nil
	}
	if n <= 365 && n > 0 {
		return "true", nil
	}
	return "false", nil
}

func LoginDefsPassMinDaysOK() (string, error) {
	m := readLoginDefs()
	v, ok := m["PASS_MIN_DAYS"]
	if !ok {
		return "false", nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return "false", nil
	}
	if n >= 1 {
		return "true", nil
	}
	return "false", nil
}

func LoginDefsPassWarnAgeOK() (string, error) {
	m := readLoginDefs()
	v, ok := m["PASS_WARN_AGE"]
	if !ok {
		return "false", nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return "false", nil
	}
	if n >= 7 {
		return "true", nil
	}
	return "false", nil
}

func UseraddInactiveOK() (string, error) {
	// read defaults: /etc/default/useradd contains INACTIVE=<days> on Rocky/RHEL
	b, err := os.ReadFile("/etc/default/useradd")
	if err != nil {
		return "unknown", err
	}
	s := strings.ToLower(string(b))
	// find INACTIVE= value
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inactive=") {
			v := strings.TrimPrefix(line, "inactive=")
			v = strings.TrimSpace(v)
			n, err := strconv.Atoi(v)
			if err != nil {
				return "false", nil
			}
			if n <= 30 && n >= 0 {
				return "true", nil
			}
			return "false", nil
		}
	}
	return "false", nil
}
