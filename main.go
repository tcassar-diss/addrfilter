package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"

	"github.com/tcassar-diss/addrfilter/bpf"
	"github.com/tcassar-diss/addrfilter/frontend"
	"go.uber.org/zap"
)

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

	go func() {
		for range stopper {
			cancel()

			return
		}
	}()

	if err := command.Start(); err != nil {
		log.Fatalf("failed to launch %s%s: %v", os.Args[2], fmt.Sprintf(" %s", os.Args[3:]), err)
	}

	if err := frontend.Start(
		logger,
		int32(command.Process.Pid),
		os.Args[1],
		&frontend.StartCfg{
			WarnMode: bpf.Warn,
			Profile:  false,
		},
	); err != nil {
		log.Fatalf("failed to start filter: %v\n", err)
	}

	if err := command.Wait(); err != nil {
		if err.Error() != "signal: interrupt" {
			log.Fatalf("failed waiting on the executable: %v", err)
		}

		logger.Warnw("command killed by SIGINT", "cmd", os.Args[2])
	}
}
