package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"go.uber.org/zap"
)

// Kill will kill a processes.
func Kill(ctx context.Context, logger *zap.SugaredLogger, pids <-chan int32) error {
	var pid int32
	for {
		select {
		case <-ctx.Done():
			logger.Infow("kill context cancelled, exiting...")
			return nil
		case pid = <-pids:
		}

		logger.Infow("killing process", "pid", pid)

		if err := kill(pid); err != nil {
			// todo: shouldn't exit the security filter
			return fmt.Errorf("failed to kill pid %d: %w", pid, err)
		}
	}
}

func kill(pid int32) error {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	if err := p.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process: %w", err)
	}

	return nil
}
