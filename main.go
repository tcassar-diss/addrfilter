package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/tcassar-diss/addrfilter/bpf"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func main() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get zap production logger: %v", err)
	}

	logger := l.Sugar()
	defer l.Sync()

	prog, err := bpf.LoadProgram(logger)
	if err != nil {
		logger.Fatalw("failed to load bpf program", "err", err)
	}

	logger.Infow("program loaded successfully")

	if len(os.Args) < 2 {
		fmt.Println("usage: addrfilter [PID] (incorrect number of args supplied)")
		os.Exit(1)
	}

	p, err := strconv.ParseInt(os.Args[1], 10, 32)
	if err != nil {
		fmt.Println("couldn't parse PID provided")
		os.Exit(1)
	}

	pid := int32(p)

	ctx, cancel := context.WithCancel(context.Background())

	var eg errgroup.Group

	eg.Go(func() error {
		return prog.Filter(ctx, pid)
	})

	time.Sleep(time.Second)
	cancel()

	if err := eg.Wait(); err != nil {
		logger.Fatalw("error occurred while filtering", "err", err)
	}

	stats, err := prog.ReadStatsMap()
	if err != nil {
		logger.Fatalw("couldn't read stats map", "err", err)
	}

	logger.Info("protection finished")
	logger.Infow("execution stats",
		"tp_entered", stats.TPEntered,
		"get_current_task_failed", stats.GetCurrentTaskFailed,
		"ignore_pid", stats.IgnorePID,
	)
}
