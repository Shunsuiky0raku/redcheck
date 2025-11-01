package checks

import (
	"bufio"
	"os"
	"strings"
)

func hasSeparateMount(path string) (bool, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// fields: src, target, fstype, options, ...
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == path {
			return true, nil
		}
	}
	return false, nil
}
