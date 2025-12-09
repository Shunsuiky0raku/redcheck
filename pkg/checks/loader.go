package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//
// Load built-in rules from pkg/checks/rules.yaml
//
func LoadBuiltInRules() ([]Rule, error) {
	data, err := os.ReadFile("pkg/checks/rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("read built-in rules.yaml: %w", err)
	}

	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("unmarshal built-in rules.yaml: %w", err)
	}

	return rules, nil
}

//
// LoadRulesFromDir – loads rules from a directory of .yml/.yaml files
//
// Supports:
//   - A file containing:  [ { rule }, { rule } ]
//   - A file containing:  { rule }
//
func LoadRulesFromDir(dir string) ([]Rule, error) {
	var out []Rule

	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		// Only parse YAML files
		if !strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}

		// Try unmarshalling as []Rule first
		var many []Rule
		if err := yaml.Unmarshal(data, &many); err == nil {
			if len(many) > 0 {
				out = append(out, many...)
				return nil
			}
		}

		// Try unmarshalling as a single rule
		var single Rule
		if err := yaml.Unmarshal(data, &single); err != nil {
			return fmt.Errorf("unmarshal %s as []Rule or Rule: %w", p, err)
		}

		if strings.TrimSpace(single.ID) == "" {
			return fmt.Errorf("unmarshal %s: rule missing ID", p)
		}

		out = append(out, single)
		return nil
	})

	return out, err
}

