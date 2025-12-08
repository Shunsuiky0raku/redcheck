package checks

import (
	"fmt"
	"sort"
	"strings"
)

func BuildFixScript(results []CheckResult) string {
	var fixes []CheckResult

	for _, r := range results {
		if r.Status == "fail" && r.Remediation != "" {
			fixes = append(fixes, r)
		}
	}

	sort.Slice(fixes, func(i, j int) bool {
		return fixes[i].Severity > fixes[j].Severity
	})

	var b strings.Builder
	b.WriteString("#!/bin/bash\n\nset -e\n\n")

	for _, r := range fixes {
		b.WriteString(fmt.Sprintf("echo \"Fixing %s (%s)\"\n", r.Title, r.ID))
		b.WriteString("# Remediation:\n")
		b.WriteString(fmt.Sprintf("# %s\n\n", r.Remediation))
	}

	return b.String()
}

