package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/tcassar-diss/addrfilter/bpf"
	"github.com/tcassar-diss/addrfilter/frontend"
	"go.uber.org/zap"
)

const (
	IsolatedUID = 1000
	IsolatedGID = 1000
)

func initFilter(logger *zap.SugaredLogger) (*bpf.Filter, error) {
	libcRange, err := frontend.FindLibc(fmt.Sprintf("/proc/%d/maps", os.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("failed to get libc range for current process: %w", err)
	}

	parsedWLs, err := frontend.ParseSysoWhitelists(os.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse whitelists: %w", err)
	}

	whitelists := bpf.ParseMapWhitelists(parsedWLs.NameSyscallMap)

	cfg := bpf.DefaultFilterCfg()

	filter, err := bpf.NewFilter(logger, bpf.NewLibcRange(libcRange.Start, libcRange.End), whitelists, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new Filter: %w", err)
	}

	return filter, nil
}

func logStats(filter *bpf.Filter) {
	stats, err := filter.ReadStatsMap()
	if err != nil {
		log.Fatalf("failed to read stats map: %v", err)
	}

	bts, err := json.Marshal(stats)
	if err != nil {
		log.Fatalf("failed to marshal stats: %v", err)
	}

	fmt.Println(string(bts))
}

func main() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get zap production logger: %v\n", err)
	}

	logger := l.Sugar()
	defer logger.Sync()

	if len(os.Args) < 3 {
		log.Fatalf("expected (at least) two args: whitelist, and executable (+ args)\n")
	}

	ctx, cancel := context.WithCancel(context.Background())

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	command := exec.CommandContext(ctx, os.Args[2], os.Args[3:]...)
	command.Stdout = os.Stdout

	// this script expects to be run as root to be able to mount BPF programs,
	// etc. running the filtered program as root would be a bad idea.
	//
	// therefore, use namespaces to remove process privileges (sort of);
	// TLDR is that now process can't mess with BPF!
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: IsolatedUID,
			Gid: IsolatedGID,
		},
	}

	go func() {
		for range stopper {
			cancel()

			return
		}
	}()

	filter, err := initFilter(logger)
	if err != nil {
		log.Fatalf("failed to create filter: %v", err)
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	go func() {
		errChan <- filter.Start(ctx)
	}()

	if err = command.Start(); err != nil {
		log.Fatalf("failed to launch %s%s: %v", os.Args[2], fmt.Sprintf(" %s", os.Args[3:]), err)
	}

	if err = filter.ProtectPID(int32(command.Process.Pid)); err != nil {
		log.Fatalf("failed to protect executable: %v", err)
	}

	err = command.Wait()
	if err != nil {
		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			ws := exitErr.Sys().(syscall.WaitStatus)

			if ws.Signaled() && ws.Signal() == syscall.SIGINT {
				logger.Warnw("command interrupted by SIGINT", "cmd", os.Args[2])
			} else {
				logger.Errorw("command exited with error", "exitCode", ws.ExitStatus(), "signal", ws.Signal(), "cmd", os.Args[2])
			}
		} else {
			logger.Fatalw("failed waiting on executable", "err", err)
		}
	}

	cancel()

	if err = <-errChan; err != nil {
		log.Fatalf("error encountered while filtering: %v", err)
	}

	logStats(filter)
}
