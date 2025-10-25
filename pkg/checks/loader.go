package checks

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromDir reads *.yml/*.yaml in dir and returns appended rules.
// Supports both a single Rule doc and a YAML list of Rule.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errors.New("rules path is not a directory")
	}

	patterns := []string{"*.yml", "*.yaml"}
	var paths []string
	for _, pat := range patterns {
		glob, _ := filepath.Glob(filepath.Join(dir, pat))
		paths = append(paths, glob...)
	}
	var out []Rule
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var list []Rule
		if err := yaml.Unmarshal(b, &list); err == nil && len(list) > 0 {
			out = append(out, list...)
			continue
		}
		var one Rule
		if err := yaml.Unmarshal(b, &one); err == nil && one.ID != "" {
			out = append(out, one)
		}
	}
	return out, nil
}
