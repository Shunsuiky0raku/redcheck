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

// Rule describes a rule loaded from YAML
type Rule struct {
    ID          string   `yaml:"id"`
    Title       string   `yaml:"title"`
    Category    string   `yaml:"category"`
    Severity    string   `yaml:"severity"`
    Fact        string   `yaml:"fact"`
    Expected    string   `yaml:"expected"`
    ExpectedAll []string `yaml:"expected_allof"`
    Remediation string   `yaml:"remediation"`
    FilePath    string   `yaml:"file"`
    Tags        []string `yaml:"tags"`
}

// Tag helper
func (r Rule) HasTag(tag string) bool {
    for _, t := range r.Tags {
        if t == tag {
            return true
        }
    }
    return false
}

// Identify privilege-escalation rules
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

