package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/tcassar-diss/addrfilter/frontend"
	"github.com/urfave/cli/v2"
)

var (
	killAll bool
	warn    bool
)

func main() {
	gCfg := &frontend.GeneratorCfg{
		WhitelistPath: "",
		Options:       &frontend.GlobalFlags{},
		CmdCfg:        &frontend.CmdCfg{},
	}

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "spawn-root",
				Usage:       "spawn the executable with root privileges. ONLY FOR DEVELOPMENT USE!",
				Destination: &gCfg.CmdCfg.SpawnRoot,
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
		Name:      "afgen",
		ArgsUsage: "<executable> [exec args...]",
		Usage:     "generate a whitelist for addrfilter",
		Action: func(cCtx *cli.Context) error {
			if nArgs := cCtx.Args().Len(); nArgs < 1 {
				_ = cli.ShowAppHelp(cCtx)

				return cli.Exit(
					fmt.Sprintf("\nERROR: Too few arguments! Expected >1, got %d", nArgs),
					1,
				)
			}

			gCfg.CmdCfg.ExecPath = cCtx.Args().Get(0)
			gCfg.CmdCfg.ExecArgs = cCtx.Args().Slice()[1:]

			execName := filepath.Base(gCfg.CmdCfg.ExecPath)

			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to getwd: %w", err)
			}

			gCfg.WhitelistPath = path.Join(wd, fmt.Sprintf("%s-whitelist.toml", execName))

			if gCfg.Options.Verbose {
				bts, err := json.Marshal(gCfg)
				if err != nil {
					panic(err)
				}

				fmt.Println(string(bts))
			}

			if err := frontend.RunGenerator(gCfg); err != nil {
				return cli.Exit(
					fmt.Sprintf("addrfilter encounted an error while generating a whitelist it couldn't recover from: %v", err),
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
