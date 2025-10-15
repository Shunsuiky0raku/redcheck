package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "redcheck",
	Short: "RedCheck – lightweight CIS + recon scanner for Rocky/RHEL",
	Long:  "RedCheck scans a Linux host for high-ROI CIS Rocky v10 items and attacker-centric signals, then scores the posture with transparent math.",
}

// Execute is called by main.main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// global/persistent flags go here if we need them later
}
