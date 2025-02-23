package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"

	"github.com/tcassar-diss/addrfilter/bpf"
	"go.uber.org/zap"
)

func main() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get zap production logger: %v", err)
	}

	logger := l.Sugar()
	defer l.Sync()

	cfg := bpf.FilterCfg{
		Action: bpf.KillAll,
	}

	filter, err := bpf.LoadFilter(logger, &cfg)
	if err != nil {
		logger.Fatalw("failed to load bpf program", "err", err)
	}

	logger.Infow("program loaded successfully")

	if len(os.Args) < 2 {
		fmt.Println("usage: addrfilter [PID] (incorrect number of args supplied)")
		os.Exit(1)
	}

	i64pid, err := strconv.ParseInt(os.Args[1], 10, 32)
	if err != nil {
		fmt.Println("couldn't parse PID provided")
		os.Exit(1)
	}

	pid := int32(i64pid)

	if err := filter.ProtectPID(pid); err != nil {
		logger.Fatalw("failed to protect pid", "pid", pid, "err", err)
	}

	job := ProtectJob{
		PID: pid,
		Whitelists: []*bpf.Whitelist{
			{
				Filename: "print",
				Syscalls: func() []uint {
					w := make([]uint, 461)
					for i := range 461 {
						w[i] = uint(0) // allow none for dev purposes
					}

					return w
				}(),
			},
		},
		Cfg: &cfg,
	}

	if err = job.Register(filter); err != nil {
		logger.Fatalw("failed to register protection job", "err", err)
	}

	logger.Infow("loaded protection job")

	ctx, cancel := context.WithCancel(context.Background())

	// needs to be buffered s.th. select/case statements don't block
	stopper := make(chan os.Signal, 1)

	signal.Notify(stopper, os.Interrupt)

	go func() {
		for {
			select {
			case <-stopper:
				logger.Infow("received ctrl-c, exiting")
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := filter.Start(ctx); err != nil {
		cancel()
		logger.Fatalw("error occurred while filtering", "err", err)
	}

	stats, err := filter.ReadStatsMap()
	if err != nil {
		logger.Fatalw("couldn't read stats map", "err", err)
	}

	if _, err := filter.ReadStacktraceMap(); err != nil {
		logger.Fatalw("couldn't read stacktrace debug map: %w", err)
	}

	bts, err := json.Marshal(&stats)
	if err != nil {
		logger.Fatalw("failed to marshall stats", "err", err)
	}

	fmt.Println(string(bts))
}
