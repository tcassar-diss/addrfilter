package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/tcassar-diss/addrfilter/bpf"
)

var (
	warnFlag    bool
	killAllFlag bool
)

// ApplyFlags is a helper function to add flags to subcommands.
func applyFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&warnFlag, "warn", false, "Set action to Warn")
	cmd.Flags().BoolVar(&killAllFlag, "killall", false, "Set action to KillAll")
}

// ResolveAction determines which action to take
func getWarnmode() bpf.WarnMode {
	if killAllFlag {
		return bpf.KillAll
	}

	if warnFlag {
		return bpf.Warn
	}

	return bpf.KillPID
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "addrfilter",
	Short: "Fine-grained system call filtering based on process address space",
	Long:  `Fine-grained system call filtering based on process address space`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {}
