package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/tcassar-diss/addrfilter/bpf"
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
	addrfilter protect [PID] [SYSO_WHITELIST.json]
where
	[PID] is the process ID to filter. All child processes spawned while the filter is active will also be covered.
	[SYSO_WHITELIST] is a path to a syso-generated set of syscalls and their calling libraries.
`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		l, err := zap.NewProduction()
		if err != nil {
			log.Fatalf("failed to get zap production logger: %v", err)
		}

		logger := l.Sugar()
		defer logger.Sync()

		params, err := parseParams(cmd, args)
		if err != nil {
			logger.Fatalw("invalid arguments (addrfilter -h for help)", "err", err)
		}

		filter, err := bpf.LoadFilter(
			logger,
			&bpf.FilterCfg{
				Action: params.warnmode,
			},
		)
		if err != nil {
			logger.Fatalw("failed to load filter", "err", err)
		}

		whitelists, err := buildWhitelists(params.whitelistPath)

		job := frontend.NewProtectJob(logger, params.pid, whitelists, filter)

		if err := job.Run(ctx); err != nil {
			logger.Fatalw("fatal error during process protection", "pid", params.pid, "err", err)
		}

		stats, err := job.Stats()
		if err != nil {
			logger.Fatalw("failed to read stats about protection", "err", err)
		}

		bts, err := json.Marshal(&stats)
		if err != nil {
			logger.Fatalw("failed to marshal stats to json", "err", err)
		}

		fmt.Println(string(bts))
	},
}

func init() {
	rootCmd.AddCommand(protectCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// protectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// protectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	protectCmd.Flags().String(
		"warnmode",
		"",
		"Set behavior for non-whitelisted syscalls (warn, killall).Default is killpid.",
	)
}

type params struct {
	pid           int32
	whitelistPath string
	warnmode      bpf.WarnMode
}

func parseParams(cmd *cobra.Command, args []string) (*params, error) {
	wmFlag, err := cmd.Flags().GetString("warnmode")
	if err != nil {
		return nil, fmt.Errorf("failed to get warnmode flag: %w", err)
	}

	var warnmode bpf.WarnMode
	switch wmFlag {
	case "warn":
		warnmode = bpf.Warn
	case "killall":
		warnmode = bpf.KillAll
	case "":
		warnmode = bpf.KillPID // Default behavior
	default:
		return nil, fmt.Errorf("invalid warnmode: %s (expected warn, killall, or empty for default)", wmFlag)
	}

	i64pid, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to an int: %w", args[0], err)
	}

	pid := int32(i64pid)

	if _, err := os.Stat(args[1]); err != nil {
		return nil, fmt.Errorf("failed to find file at path %s: %w", args[1], err)
	}

	return &params{
		pid:           pid,
		whitelistPath: args[1],
		warnmode:      warnmode,
	}, nil
}

func buildWhitelists(fp string) ([]*bpf.Whitelist, error) {
	bts, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return bpf.ParseSysoWhitelists(bts)
}
