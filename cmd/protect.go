package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/tcassar-diss/addrfilter/frontend"
	"go.uber.org/zap"
)

// protectCmd represents the protect command
var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Protect will apply a whitelist filter to an already running process.",
	Long: `
Protect will apply a whitelist filter to an already running process.
USAGE
	addrfilter protect [SYSO_WHITELIST.json] [PID]
where
	[PID] is the process ID to filter. All child processes spawned while the filter is active will also be covered.
	[SYSO_WHITELIST] is a path to a syso-generated set of syscalls and their calling libraries.
`,
	Run: func(cmd *cobra.Command, args []string) {
		l, err := zap.NewProduction()
		if err != nil {
			log.Fatalf("failed to get zap production logger: %v", err)
		}

		logger := l.Sugar()
		defer logger.Sync()

		params, err := parseProtectParams(args)
		if err != nil {
			logger.Fatalw("invalid arguments (addrfilter -h for help)", "err", err)
		}

		if err := frontend.Start(logger, params.pid, params.warnmode, args[0]); err != nil {
			logger.Fatalw("failed to protect", "pid", params.pid, "err", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(protectCmd)
	applyFlags(protectCmd)
}
