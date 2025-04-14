package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/tcassar-diss/addrfilter/bpf"
	"github.com/tcassar-diss/addrfilter/frontend"
	"github.com/urfave/cli/v2"
)

func main() {
	cfg := &frontend.AddrfilterCfg{
		Options: &frontend.AddrfilterFlags{},
	}

	var (
		killAll bool
		warn    bool
	)

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "profile",
				Usage:       "enable profiling mode (requires compiling with PROFILE macro defined)",
				Aliases:     []string{"p"},
				Destination: &cfg.Options.Profile,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Usage:       "run the frontend in verbose mode; provides a dump of execution stats when complete",
				Aliases:     []string{"v"},
				Destination: &cfg.Options.Verbose,
			},
			&cli.BoolFlag{
				Name:        "toml",
				Usage:       "needed when whitelists are in TOML format",
				Destination: &cfg.Options.TomlWhitelist,
			},
			&cli.BoolFlag{
				Name:        "spawn-root",
				Usage:       "spawn the executable with root privileges. ONLY FOR DEVELOPMENT USE!",
				Destination: &cfg.Options.SpawnRoot,
			}, &cli.BoolFlag{
				Name:        "kill-all",
				Usage:       "configures addrfilter to kill all tracked processes if one trips the filter; overrides warn",
				Destination: &killAll,
			}, &cli.BoolFlag{
				Name:        "warn",
				Usage:       "configures addrfilter to only warn the user whenever a process trips the filter",
				Destination: &warn,
			},
		},
		Name:      "addrfilter",
		ArgsUsage: "<whitelist path> <executable> [exec args...]",
		Usage:     "fine grained system call filtering",
		Action: func(cCtx *cli.Context) error {
			if nArgs := cCtx.Args().Len(); nArgs < 2 {
				_ = cli.ShowAppHelp(cCtx)

				return cli.Exit(
					fmt.Sprintf("\nERROR: Too few arguments! Expected >2, got %d", nArgs),
					1,
				)
			}

			cfg.WhitelistPath = cCtx.Args().Get(0)
			cfg.ExecPath = cCtx.Args().Get(1)
			cfg.ExecArgs = cCtx.Args().Slice()[2:]

			if warn {
				cfg.WarnMode = &bpf.Warn
			} else if killAll {
				cfg.WarnMode = &bpf.KillAll
			} else {
				cfg.WarnMode = &bpf.KillPID
			}

			bts, err := json.Marshal(cfg)
			if err != nil {
				panic(err)
			}

			if cfg.Options.Verbose {
				fmt.Println(string(bts))
			}

			if err := frontend.Run(cfg); err != nil {
				return cli.Exit(
					fmt.Sprintf("addrfilter encounted an error it couldn't recover from: %v", err),
					2,
				)
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
