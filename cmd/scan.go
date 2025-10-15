package cmd

import (
	"fmt"
	"time"

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
		fmt.Printf("Starting scan… (all=%v, cis=%v, pe=%v, timeout=%s)\n", flagAll, flagCIS, flagPE, flagTimeout)
		if jsonOut != "" {
			fmt.Println("Will write JSON to:", jsonOut)
		}
		if htmlOut != "" {
			fmt.Println("Will write HTML to:", htmlOut)
		}
		// TODO: call pkg/host, pkg/checks, pkg/scoring, pkg/report
		fmt.Println("Scan complete (stub).")
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
