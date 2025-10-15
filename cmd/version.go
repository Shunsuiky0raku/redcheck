package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	buildVersion = "0.0.1-dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version/build info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("redcheck %s (commit %s, built %s)\n", buildVersion, buildCommit, buildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
