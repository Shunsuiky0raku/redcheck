package checks

import (
	_ "embed"
	"encoding/json"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Title       string   `yaml:"title" json:"title"`
	Category    string   `yaml:"category" json:"category"`
	Fact        string   `yaml:"fact" json:"fact"`
	Expected    string   `yaml:"expected,omitempty" json:"expected,omitempty"`
	ExpectedAll []string `yaml:"expected_allof,omitempty" json:"expected_allof,omitempty"`
	Severity    string   `yaml:"severity" json:"severity"`
	Remediation string   `yaml:"remediation" json:"remediation"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

//go:embed rules.yaml
var rulesYAML []byte

func LoadRules() ([]Rule, error) {
	var rs []Rule
	if err := yaml.Unmarshal(rulesYAML, &rs); err != nil {
		return nil, err
	}
	return rs, nil
}

func MustRulesAsJSON() string {
	rs, _ := LoadRules()
	b, _ := json.MarshalIndent(rs, "", "  ")
	return string(b)
}
