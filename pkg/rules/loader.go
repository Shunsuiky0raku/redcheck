package rules

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"path/filepath"
)

type Rule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Category    string `yaml:"category"`
	Fact        string `yaml:"fact"`
	Expected    string `yaml:"expected"`
	Severity    string `yaml:"severity"`
	Remediation string `yaml:"remediation"`
}

func LoadFromDir(dir string) ([]Rule, error) {
	var rules []Rule
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			continue
		}
		var r Rule
		if err := yaml.Unmarshal(data, &r); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}
