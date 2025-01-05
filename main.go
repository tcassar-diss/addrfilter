package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"

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

	filter, err := bpf.LoadFilter(logger)
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

	ctx, cancel := context.WithCancel(context.Background())

	// needs to be buffered s.th. select/case statements don't block
	kills := make(chan int32, 16)
	stopper := make(chan os.Signal)

	signal.Notify(stopper, os.Interrupt)

	go func() {
		<-stopper
		logger.Infow("received ctrl-c, exiting")
		cancel()
	}()

	var eg errgroup.Group

	eg.Go(func() error {
		return filter.Start(ctx, kills)
	})

	eg.Go(func() error {
		return Kill(ctx, logger, kills)
	})

	if err := eg.Wait(); err != nil {
		logger.Fatalw("error occurred while filtering", "err", err)
	}

	stats, err := filter.ReadStatsMap()
	if err != nil {
		logger.Fatalw("couldn't read stats map", "err", err)
	}

	logger.Info("protection finished")
	logger.Infow("execution stats",
		"tp_entered", stats.TPEntered,
		"get_current_task_failed", stats.GetCurrentTaskFailed,
		"ignore_pid", stats.IgnorePID,
		"read_pid_failed", stats.ReadPIDFailed,
		"ringbuf_reserve_failed", stats.RingbufReserveFailed,
	)
}
