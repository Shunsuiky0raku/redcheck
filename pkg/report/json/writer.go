package jsonreport

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
)

type Report struct {
	Host struct {
		Hostname string `json:"hostname"`
		Time     string `json:"time"`
	} `json:"host"`
	Results []checks.CheckResult `json:"results"`
	// Scores will be added next
}

func Write(path string, results []checks.CheckResult) error {
	var r Report
	r.Host.Time = time.Now().UTC().Format(time.RFC3339)
	// (basic hostname; replace with real host facts later)
	if h, err := os.Hostname(); err == nil {
		r.Host.Hostname = h
	}

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
