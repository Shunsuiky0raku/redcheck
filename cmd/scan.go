package cmd

import (
	"fmt"
	"time"

	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	jsonreport "github.com/Shunsuiky0raku/redcheck/pkg/report/json"
	"github.com/spf13/cobra"
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

		// write HTML later
		if htmlOut != "" {
			fmt.Println("Will write HTML to:", htmlOut)
			// TODO: call html reporter
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
