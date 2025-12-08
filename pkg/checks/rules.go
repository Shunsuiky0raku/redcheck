package checks

// FilterForMode selects rules based on flags.
func FilterForMode(all, cis, pe bool, rules []Rule) []Rule {
	var out []Rule

	for _, r := range rules {
		if all {
			out = append(out, r)
			continue
		}
		if cis && r.HasTag("cis") {
			out = append(out, r)
			continue
		}
		if pe && r.HasTag("recon") {
			out = append(out, r)
			continue
		}
	}
	return out
}

