package wlgen

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
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
	libcRange  *wlgenVmRange
	whitelists []*bpf.Whitelist
	tracepoint *link.Link
	objects    *wlgenObjects
}

func NewWLGenerator(
	logger *zap.SugaredLogger,
) (*WLGenerator, error) {
	g := &WLGenerator{
		logger:  logger,
		objects: &wlgenObjects{},
	}

	if err := g.init(); err != nil {
		return nil, fmt.Errorf("failed to initialse wl-generator: %w", err)
	}

	return g, nil
}

func (g *WLGenerator) init() error {
	if err := loadWlgenObjects(g.objects, nil); err != nil {
		return fmt.Errorf("failed to load wlgen objects: %w", err)
	}

	return nil
}

// Start mounts the bpf tracepoint to generate whitelists. Start is blocking!
func (g *WLGenerator) Start(ctx context.Context) error {
	if err := g.regLibc(); err != nil {
		return fmt.Errorf("failed to register libc address: %w", err)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: g.objects.Wlgen,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to raw tracepoint: %w", err)
	}
	defer tp.Close()

	for range ctx.Done() {
	}

	return nil
}

// MonitorPID registers a process ID in the filtering map, therefore applying
// the whitelists to the process.
func (g *WLGenerator) MonitorPID(pid int32) error {
	g.logger.Infow("adding process to filter list", "pid", pid)

	if err := g.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}

	return nil
}

func (g *WLGenerator) SetLibc(start uint64, end uint64) {
	g.libcRange = &wlgenVmRange{
		Start: start,
		End:   end,
	}
}

func (g *WLGenerator) ReadWhitelists() (map[string][]uint, error) {
	var (
		filename [256]byte
		syscalls wlgenSyscallWhitelist
	)

	whitelists := make(map[string][]uint)
	nextWhitelist := g.objects.PathWhitelistMap.Iterate()

	for {
		next := nextWhitelist.Next(&filename, &syscalls)

		if err := nextWhitelist.Err(); err != nil {
			return nil, fmt.Errorf("failed to read whitelist: %w", err)
		}

		name := strings.Trim(string(filename[:]), "\u0000")

		whitelists[name] = g.bitmapToUints(syscalls)

		if !next {
			break
		}
	}

	return whitelists, nil
}

func (g *WLGenerator) regLibc() error {
	if g.libcRange == nil {
		return fmt.Errorf("%w: libc range not initialised", bpf.ErrBadLibcRange)
	}

	if g.libcRange.Start == 0 {
		g.logger.Warn("start address is 0!")
	}

	start := g.libcRange.Start
	end := g.libcRange.End

	if end <= start {
		return fmt.Errorf("%w: end cannot be less than start", bpf.ErrBadLibcRange)
	}

	g.logger.Infow("updating libc address space",
		"start", fmt.Sprintf("0x%x", start),
		"end", fmt.Sprintf("0x%x", end),
	)

	zero := 0

	if err := g.objects.LibcRangeMap.Put(
		int32(zero),
		// &wlgenVmRange{
		// 	Start: 0x7ffff7000000,
		// 	End:   0x7ffff7205000,
		// },
		&wlgenVmRange{
			Start: start,
			End:   end,
		},
	); err != nil {
		return fmt.Errorf("failed to insert vmrange for pid: %w", err)
	}

	return nil
}

func (g *WLGenerator) bitmapToUints(bitmap wlgenSyscallWhitelist) []uint {
	var results []uint

	for byteIndex, byteVal := range bitmap.BitArray {
		for bitIndex := range 8 {
			if byteVal&(1<<bitIndex) != 0 {
				syscallNum := uint(byteIndex*8 + bitIndex)
				results = append(results, syscallNum)
			}
		}
	}

	return results
}
