package frontend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/tcassar-diss/addrfilter/bpf"
	"github.com/tcassar-diss/addrfilter/bpf/filter"
	"go.uber.org/zap"
)

const (
	IsolatedUID = 1000
	IsolatedGID = 1000
)

type CmdCfg struct {
	ExecArgs  []string
	ExecPath  string
	SpawnRoot bool // spawn the filtered application as root (DEVELOPMENT ONLY)
}

type GlobalFlags struct {
	Profile       bool // profile BPF
	Verbose       bool // run frontend in verbose mode
	SysoWhitelist bool
}

type AddrfilterCfg struct {
	WhitelistPath string
	WarnMode      *filter.WarnMode
	Options       *GlobalFlags
	CmdCfg        *CmdCfg
}

func RunAddrfilter(cfg *AddrfilterCfg) error {
	logger, err := initLogger()
	if err != nil {
		return fmt.Errorf("failed to get a logger: %w", err)
	}

	logger.Infoln("=== Launching addrfilter ===")
	defer logger.Sync()

	ctx := context.Background()

	cmd := configureCommand(ctx, cfg.CmdCfg)

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)

	filter, closeFn, err := initFilter(logger, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialise filter: %w", err)
	}

	if closeFn != nil {
		defer closeFn()
	}

	errChan := make(chan error, 1)
	defer close(errChan)

	go func() {
		errChan <- filter.Start(ctx)
	}()

	if err = cmd.Start(); err != nil {
		log.Fatalf("failed to launch %s%s: %v", cfg.CmdCfg.ExecPath, fmt.Sprintf(" %s", cfg.CmdCfg.ExecArgs), err)
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
		log.Fatalf("error encountered while filtering: %v", err)
	}

	if cfg.Options.Verbose {
		logStats(logger, filter)
	}

	return nil
}

func initLogger() (*zap.SugaredLogger, error) {
	l, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to get production zap logger: %w", err)
	}

	return l.Sugar(), nil
}

func configureCommand(ctx context.Context, cfg *CmdCfg) *exec.Cmd {
	cmd := exec.CommandContext(ctx, cfg.ExecPath, cfg.ExecArgs...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// this script expects to be run as root to be able to mount BPF programs,
	// etc. running the filtered program as root would be a bad idea.
	//
	// therefore, use namespaces to remove process privileges (sort of);
	// TLDR is that now process can't mess with BPF!
	if !cfg.SpawnRoot {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: IsolatedUID,
				Gid: IsolatedGID,
			},
		}
	}

	return cmd
}

func initFilter(logger *zap.SugaredLogger, cfg *AddrfilterCfg) (*filter.Filter, func() error, error) {
	// use this process's libc address range (spawned process will have the same
	// range so may as well set up before the process starts)
	libcRange, err := FindLibc(fmt.Sprintf("/proc/%d/maps", os.Getpid()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get libc range for current process: %w", err)
	}

	var parsedWLs *Whitelist

	if cfg.Options.SysoWhitelist {
		parsedWLs, err = ParseSysoWhitelists(cfg.WhitelistPath)
	} else {
		parsedWLs, err = ParseTOMLWhitelists(cfg.WhitelistPath)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse whitelists: %w", err)
	}

	whitelists := bpf.ParseMapWhitelists(parsedWLs.NameSyscallMap)

	var (
		profileDest io.Writer
		closeFn     func() error
	)

	if cfg.Options.Profile {
		f, err := os.Create(fmt.Sprintf("%s-prof.csv", cfg.CmdCfg.ExecPath))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create an output file for profiler data: %w", err)
		}

		profileDest = f
	}

	fCfg := &filter.FilterCfg{
		WarnMode:   *cfg.WarnMode,
		ProfWriter: profileDest,
	}

	filter, err := filter.NewFilter(logger, bpf.NewLibcRange(libcRange.Start, libcRange.End), whitelists, fCfg)
	if err != nil {
		return nil, closeFn, fmt.Errorf("failed to create a new Filter: %w", err)
	}

	return filter, closeFn, nil
}

func logStats(logger *zap.SugaredLogger, filter *filter.Filter) {
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
