package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	BuildVersion = "dev"
	BuildCommit  = "none"
	BuildDate    = "unknown"
)

// versionCmd prints build info
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show RedCheck version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("RedCheck %s (commit %s, built %s)\n", BuildVersion, BuildCommit, BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
