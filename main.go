package main

import (
	"context"
	"encoding/json"
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

	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 1, // TODO: replace with sensible UID
			Gid: 1, // TODO: replace with desired GID
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

	go func() {
		err = filter.Start(ctx)
		if err != nil {
			log.Fatalf("error when filtering: %v", err)
		}
	}()

	if err = command.Start(); err != nil {
		log.Fatalf("failed to launch %s%s: %v", os.Args[2], fmt.Sprintf(" %s", os.Args[3:]), err)
	}

	if err = filter.ProtectPID(int32(command.Process.Pid)); err != nil {
		log.Fatalf("failed to protect executable: %v", err)
	}

	if err = command.Wait(); err != nil {
		if err.Error() != "signal: interrupt" {
			log.Fatalf("failed waiting on the executable: %v", err)
		}

		logger.Warnw("command killed by SIGINT", "cmd", os.Args[2])
	}

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
