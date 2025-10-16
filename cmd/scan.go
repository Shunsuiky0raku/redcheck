package cmd

import (
	"fmt"
	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	htmlreport "github.com/Shunsuiky0raku/redcheck/pkg/report/html"
	jsonreport "github.com/Shunsuiky0raku/redcheck/pkg/report/json"
	"github.com/Shunsuiky0raku/redcheck/pkg/scoring"
	"github.com/spf13/cobra"
	"os"
	"time"
)

var (
	flagAll     bool
	flagCIS     bool
	flagPE      bool
	jsonOut     string
	htmlOut     string
	flagTimeout time.Duration
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run RedCheck scans",
	Long:  "Run CIS Rocky v10 checks and/or attacker-centric recon checks and produce JSON/HTML reports.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// default to --all if none specified
		if !flagAll && !flagCIS && !flagPE {
			flagAll = true
		}

		// load rules
		rs, err := checks.LoadRules()
		if err != nil {
			return err
		}

		// select rules (all == cis for now; we'll add tags/pe later)
		sel := make([]checks.Rule, 0, len(rs))
		for _, r := range rs {
			if flagAll || flagCIS {
				sel = append(sel, r)
			}
		}

		// evaluate
		results := make([]checks.CheckResult, 0, len(sel))
		for _, r := range sel {
			results = append(results, checks.Evaluate(r))
		}
		fmt.Printf("Evaluated %d rules.\n", len(results))
		fmt.Printf("Starting scan… (all=%v, cis=%v, pe=%v, timeout=%s)\n",
			flagAll, flagCIS, flagPE, flagTimeout)

		// write JSON if requested
		if jsonOut != "" {
			if err := jsonreport.Write(jsonOut, results); err != nil {
				return err
			}
			fmt.Println("JSON written to:", jsonOut)
		}
		if htmlOut != "" {
			h, _ := os.Hostname()
			ts := time.Now().UTC().Format(time.RFC3339)
			// recompute scores here or plumb them from the json writer—either is fine
			resIface := make([]scoring.Result, len(results))
			for i := range results {
				resIface[i] = results[i]
			}
			scores := scoring.Compute(resIface)
			if err := htmlreport.Write(htmlOut, h, ts, scores, results); err != nil {
				return err
			}
			fmt.Println("HTML written to:", htmlOut)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolVar(&flagAll, "all", false, "Run all checks (default if none specified)")
	scanCmd.Flags().BoolVar(&flagCIS, "cis", false, "Run CIS benchmark checks only")
	scanCmd.Flags().BoolVar(&flagPE, "pe", false, "Run recon/priv-esc checks only")
	scanCmd.Flags().StringVar(&jsonOut, "json", "", "Write results to JSON file")
	scanCmd.Flags().StringVar(&htmlOut, "html", "", "Write report to HTML file")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", 60*time.Second, "Per-check timeout (e.g., 60s, 2m)")
}
