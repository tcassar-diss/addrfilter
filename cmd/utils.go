package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/tcassar-diss/addrfilter/bpf"
)

type params struct {
	pid           int32
	whitelistPath string
	warnmode      bpf.WarnMode
}

func parseProtectParams(args []string) (*params, error) {
	i64pid, err := strconv.ParseInt(args[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to convert %s to an int: %w", args[0], err)
	}

	pid := int32(i64pid)

	if _, err := os.Stat(args[0]); err != nil {
		return nil, fmt.Errorf("failed to find file at path %s: %w", args[1], err)
	}

	return &params{
		pid:           pid,
		whitelistPath: args[0],
		warnmode:      getWarnmode(),
	}, nil
}
