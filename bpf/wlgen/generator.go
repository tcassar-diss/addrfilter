package wlgen

import (
	"github.com/tcassar-diss/addrfilter/bpf"
	"go.uber.org/zap"
)

// WLGenerator is a golang interface to the wlgen bpf program.
//
// Using WLGenerator takes three steps: first, calling NewWLGenerator
// produces a WLGenerator instance and does the bpf setup behind the scenes.
// Calling WLGenerator.Start() starts the whitelist generation,
type WLGenerator struct {
	logger     *zap.SugaredLogger
	libcRange  wlgenVmRange
	whitelists []*bpf.Whitelist
}
