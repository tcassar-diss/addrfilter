package main

import (
	"context"
	"log"
	"os"

	"github.com/tcassar-diss/addrfilter/bpf"
	"github.com/tcassar-diss/addrfilter/frontend"
	"go.uber.org/zap"
)

func parseArgs(args []string) *frontend.AddrfilterCfg {
	// TODO: parse properly via a CLI package
	return &frontend.AddrfilterCfg{
		WhitelistPath: args[1],
		ExecPath:      args[2],
		ExecArgs:      args[3:],
		WarnMode:      &bpf.KillPID,
		Options: &frontend.AddrfilterFlags{
			Verbose: true,
		},
	}
}

func main() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to get production logger: %v", err)
	}

	logger := l.Sugar()
	defer logger.Sync()

	ctx := context.Background()

	cfg := parseArgs(os.Args)

	frontend.Run(ctx, logger, cfg)
}
