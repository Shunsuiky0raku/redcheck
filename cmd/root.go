package cmd

import (
	"github.com/Shunsuiky0raku/redcheck/pkg/ui"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "redcheck",
	Short: "RedCheck – lightweight CIS + recon scanner for Rocky/RHEL",
	Long:  "RedCheck scans a Linux host for high-ROI CIS Rocky v10 items and attacker-centric signals, then scores the posture with transparent math.",
}

// Execute is called by main.main().
func Execute() {
	ui.Banner()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// global/persistent flags go here if we need them later
}
