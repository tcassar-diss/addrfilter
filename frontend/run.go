package frontend

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
	"go.uber.org/zap"
)

const (
	IsolatedUID = 1000
	IsolatedGID = 1000
)

type AddrfilterFlags struct {
	Profile   bool // profile BPF
	Verbose   bool // run frontend in verbose mode
	SpawnRoot bool // spawn the filtered application as root (DEVELOPMENT ONLY)
}

type AddrfilterCfg struct {
	WhitelistPath string
	ExecPath      string
	ExecArgs      []string
	WarnMode      *bpf.WarnMode
	Options       *AddrfilterFlags
}

func Run(ctx context.Context, logger *zap.SugaredLogger, cfg *AddrfilterCfg) error {
	logger.Infoln("=== Launching addrfilter ===")
	defer logger.Sync()

	cmd := configureCommand(ctx, cfg)

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)

	filter, err := initFilter(logger)
	if err != nil {
		return fmt.Errorf("failed to initialise filter: %w", err)
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	go func() {
		errChan <- filter.Start(ctx)
	}()

	if err = cmd.Start(); err != nil {
		log.Fatalf("failed to launch %s%s: %v", os.Args[2], fmt.Sprintf(" %s", os.Args[3:]), err)
	}

	if err = filter.ProtectPID(int32(cmd.Process.Pid)); err != nil {
		log.Fatalf("failed to protect executable: %v", err)
	}

	err = cmd.Wait()
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

	if cfg.Options.Verbose {
		logStats(logger, filter)
	}

	return nil
}

func configureCommand(ctx context.Context, cfg *AddrfilterCfg) *exec.Cmd {
	cmd := exec.CommandContext(ctx, cfg.ExecPath, cfg.ExecArgs...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// this script expects to be run as root to be able to mount BPF programs,
	// etc. running the filtered program as root would be a bad idea.
	//
	// therefore, use namespaces to remove process privileges (sort of);
	// TLDR is that now process can't mess with BPF!
	if !cfg.Options.SpawnRoot {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: IsolatedUID,
				Gid: IsolatedGID,
			},
		}
	}

	return cmd
}

func initFilter(logger *zap.SugaredLogger) (*bpf.Filter, error) {
	// use this process's libc address range (spawned process will have the same
	// range so may as well set up before the process starts)
	libcRange, err := FindLibc(fmt.Sprintf("/proc/%d/maps", os.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("failed to get libc range for current process: %w", err)
	}

	parsedWLs, err := ParseSysoWhitelists(os.Args[1])
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

func logStats(logger *zap.SugaredLogger, filter *bpf.Filter) {
	stats, err := filter.ReadStatsMap()
	if err != nil {
		log.Fatalf("failed to read stats map: %v", err)
	}

	bts, err := json.Marshal(stats)
	if err != nil {
		log.Fatalf("failed to marshal stats: %v", err)
	}

	logger.Infoln(string(bts))
}
