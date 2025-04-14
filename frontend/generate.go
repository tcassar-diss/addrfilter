package frontend

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

type GenerateCfg struct {
	WhitelistPath string
	Options       *GlobalFlags
	CmdCfg        *CmdCfg
}

func RunGenerate(cfg *GenerateCfg) error {
	logger, err := initLogger()
	if err != nil {
		return fmt.Errorf("failed to get a logger: %w", err)
	}

	logger.Infoln("=== Launching addrfilter **generate**===")
	defer logger.Sync()

	ctx := context.Background()

	cmd := configureCommand(ctx, cfg.CmdCfg)

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)

	// TODO: start the whitelist generation

	if err = cmd.Start(); err != nil {
		log.Fatalf("failed to launch %s%s: %v", cfg.CmdCfg.ExecPath, fmt.Sprintf(" %s", cfg.CmdCfg.ExecArgs), err)
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	err = cmd.Wait()
	if err != nil {
		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			ws := exitErr.Sys().(syscall.WaitStatus)

			if ws.Signaled() && ws.Signal() == syscall.SIGINT {
				logger.Warnw("command interrupted by SIGINT", "cmd", cfg.CmdCfg.ExecPath)
			} else {
				logger.Warnw("command exited with error", "exitCode", ws.ExitStatus(), "signal", ws.Signal(), "cmd", cfg.CmdCfg.ExecPath)
			}
		} else {
			return fmt.Errorf("failed waiting on executable: %w", err)
		}
	}

	cancel()

	if err = <-errChan; err != nil {
		log.Fatalf("error encountered while generating whitelists: %v", err)
	}

	return nil
}
