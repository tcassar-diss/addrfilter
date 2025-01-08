package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"go.uber.org/zap"
)

var killfn func(*zap.SugaredLogger, int32) error = warn

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

		if err := killfn(logger, pid); err != nil {
			return fmt.Errorf("failed to kill pid %d: %w", pid, err)
		}
	}
}

func kill(logger *zap.SugaredLogger, pid int32) error {
	logger.Infow("killing process", "pid", pid)
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	if err := p.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to kill process: %w", err)
	}

	return nil
}

func warn(logger *zap.SugaredLogger, pid int32) error {
	logger.Infow("suspicious syscalls from process", "pid", pid)

	return nil
}
