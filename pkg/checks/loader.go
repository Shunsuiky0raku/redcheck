package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadBuiltInRules loads rules.yaml from the embedded path.
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

// LoadRulesFromDir loads YAML rule files from a directory.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	var out []Rule

	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}

		var chunk []Rule
		if err := yaml.Unmarshal(data, &chunk); err != nil {
			return fmt.Errorf("unmarshal %s: %w", p, err)
		}

		out = append(out, chunk...)
		return nil
	})

	return out, err
}

