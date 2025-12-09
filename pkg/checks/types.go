package checks

// CheckResult is the final output of a rule check.
type CheckResult struct {
	ID          string   `json:"ID"`
	Title       string   `json:"Title"`
	Category    string   `json:"Category"`
	Severity    string   `json:"Severity"`
	Status      string   `json:"Status"`
	Observed    string   `json:"Observed"`
	Expected    string   `json:"Expected"`
	Evidence    string   `json:"Evidence,omitempty"`
	Remediation string   `json:"Remediation"`
	FilePath    string   `json:"FilePath,omitempty"`
	Tags        []string `json:"Tags,omitempty"`
}

// Rule describes a rule loaded from YAML.
type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Fact        string   `yaml:"fact"`
	Expected    string   `yaml:"expected"`
	ExpectedAll []string `yaml:"expected_all"` // ❤️ matches rules.yaml now
	Remediation string   `yaml:"remediation"`

	// YAML can provide either:
	//   file:  "/etc/ssh/sshd_config"
	//   files: ["/etc/ssh/sshd_config", "/etc/issue.net"]
	FilePath string   `yaml:"file"`            // optional single file
	Files    []string `yaml:"files,omitempty"` // optional list of files

	Tags []string `yaml:"tags"`
}

// HasTag checks whether the rule has a specific tag.
func (r Rule) HasTag(tag string) bool {
	for _, t := range r.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// IsPE identifies privilege-escalation / recon-style rules.
func (r Rule) IsPE() bool {
	for _, t := range r.Tags {
		if t == "recon" || t == "privilege" || t == "pe" {
			return true
		}
	}
	return false
}

// scoring.Result interface
func (c CheckResult) GetID() string       { return c.ID }
func (c CheckResult) GetSeverity() string { return c.Severity }
func (c CheckResult) GetStatus() string   { return c.Status }
func (c CheckResult) GetCategory() string { return c.Category }
