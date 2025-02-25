package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tcassar-diss/addrfilter/bpf"
	"go.uber.org/zap"
)

func Start(logger *zap.SugaredLogger, pid int32, warnmode bpf.WarnMode, whitelistPath string) error {
	filter, err := bpf.LoadFilter(
		logger,
		&bpf.FilterCfg{
			Action: warnmode,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to load filter", "err", err)
	}

	whitelists, err := buildWhitelists(whitelistPath)

	job := NewProtectJob(logger, pid, whitelists, filter)

	if err := job.Run(context.Background()); err != nil {
		return fmt.Errorf("failed to run job: %w", err)
	}

	stats, err := job.Stats()
	if err != nil {
		return fmt.Errorf("failed to read stats about protection: %w", err)
	}

	bts, err := json.Marshal(&stats)
	if err != nil {
		return fmt.Errorf("failed to marshal stats to json: %w", err)
	}

	fmt.Println(string(bts))

	return nil
}

func buildWhitelists(fp string) ([]*bpf.Whitelist, error) {
	bts, err := os.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return bpf.ParseSysoWhitelists(bts)
}
