/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"github.com/tcassar-diss/addrfilter/frontend"
	"go.uber.org/zap"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "launch",
	Short: "Launch and protect an executable",
	Long: `Launch will launch an application and apply the provided whitelist.

	USAGE
		addrfilter start [flags] /path/to/whitelist /path/to/executable args...
	where
		/path/to/executable: executable to be protected
		/path/to/whitelist: syso-generated whitelist
	`,
	Run: func(cmd *cobra.Command, args []string) {
		// todo: ctrl-c -> cancel command context
		l, err := zap.NewProduction()
		if err != nil {
			log.Fatalf("failed to get zap production logger: %v\n", err)
		}

		logger := l.Sugar()
		defer logger.Sync()

		if len(args) < 2 {
			log.Fatalf("expected (at least) two args: whitelist, and executable (+ args)\n")
		}

		// args doesn't include executable name, so args[0] == argv[1]
		command := exec.Command(args[1], args[2:]...)
		command.Stdout = os.Stdout

		if err := command.Start(); err != nil {
			log.Fatalf("failed to launch %s%s: %v", args[1], fmt.Sprintf(" %s", args[2:]), err)
		}

		time.Sleep(1 * time.Second)

		if err := frontend.Start(
			logger,
			int32(command.Process.Pid),
			args[0],
			&frontend.StartCfg{
				WarnMode: getWarnmode(),
				Profile:  getProfile(),
			},
		); err != nil {
			log.Fatalf("failed to start filter: %v\n", err)
		}

		if err := command.Wait(); err != nil {
			log.Fatalf("failed waiting on the executable: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	applyFlags(startCmd)
}
