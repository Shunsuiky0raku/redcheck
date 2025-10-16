package jsonreport

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	"github.com/Shunsuiky0raku/redcheck/pkg/scoring"
)

type Report struct {
	Host struct {
		Hostname string `json:"hostname"`
		Time     string `json:"time"`
	} `json:"host"`
	Scores  scoring.Scores       `json:"scores"`
	Results []checks.CheckResult `json:"results"`
}

func Write(path string, results []checks.CheckResult) error {
	var r Report
	r.Host.Time = time.Now().UTC().Format(time.RFC3339)
	if h, err := os.Hostname(); err == nil {
		r.Host.Hostname = h
	}
	// compute scores
	resIface := make([]scoring.Result, len(results))
	for i := range results {
		resIface[i] = results[i]
	}
	r.Scores = scoring.Compute(resIface)
	r.Results = results

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
