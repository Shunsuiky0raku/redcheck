package jsonreport

import (
	"encoding/json"
	"os"

	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	"github.com/Shunsuiky0raku/redcheck/pkg/scoring"
)

type Report struct {
	Meta struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildDate string `json:"build_date"`
	} `json:"meta"`
	Host struct {
		Hostname string `json:"hostname"`
		Time     string `json:"time"`
	} `json:"host"`
	Scores  scoring.Scores       `json:"scores"`
	Results []checks.CheckResult `json:"results"`
}

func Write(
	path string,
	results []checks.CheckResult,
	hostname, tstamp string,
	version, commit, buildDate string,
) error {
	var r Report
	// meta
	r.Meta.Version = version
	r.Meta.Commit = commit
	r.Meta.BuildDate = buildDate
	// host
	r.Host.Hostname = hostname
	r.Host.Time = tstamp
	// scores
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
