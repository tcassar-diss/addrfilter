package frontend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/tcassar-diss/addrfilter/bpf/wlgen"
)

type GeneratorCfg struct {
	WhitelistPath string
	Options       *GlobalFlags
	CmdCfg        *CmdCfg
}

func RunGenerator(cfg *GeneratorCfg) error {
	logger, err := initLogger()
	if err != nil {
		return fmt.Errorf("failed to get a logger: %w", err)
	}

	logger.Infoln("=== Launching addrfilter **generate**===")
	defer logger.Sync()

	ctx := context.Background()

	cmd := configureCommand(ctx, cfg.CmdCfg)

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)

	g, err := wlgen.NewWLGenerator(logger)
	if err != nil {
		return fmt.Errorf("failed to initialise generator: %w", err)
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	// XXX: do this with two forks so we can place the PPID in the follow map
	// before child is spawned
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("failed to launch %s%s: %v", cfg.CmdCfg.ExecPath, fmt.Sprintf(" %s", cfg.CmdCfg.ExecArgs), err)
	}

	libcRange, err := FindLibc(fmt.Sprintf("/proc/%d/maps", cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("failed to get libc range for current process: %w", err)
	}

	g.SetLibc(libcRange.Start, libcRange.End)

	go func() {
		errChan <- g.Start(ctx)
	}()

	if err = g.MonitorPID(int32(cmd.Process.Pid)); err != nil {
		return fmt.Errorf("failed to protect executable: %v", err)
	}

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
		return fmt.Errorf("error encountered while generating whitelists: %v", err)
	}

	logger.Infow("saving whitelists!")
	if err := saveWhitelists(g, cfg.WhitelistPath); err != nil {
		return fmt.Errorf("failed to save whitelists: %w", err)
	}

	return nil
}

func saveWhitelists(g *wlgen.WLGenerator, filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file for whitelists: %w", err)
	}

	wls, err := g.ReadWhitelists()
	if err != nil {
		return fmt.Errorf("failed to read whitelists: %w", err)
	}

	if err := MarshalTOMLWhitelists(f, &Whitelist{
		NameSyscallMap: wls,
	}); err != nil {
		return fmt.Errorf("failed to marshal whitelist: %w", err)
	}

	return nil
}
