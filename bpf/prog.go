package bpf

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

var ErrBadLibcRange = errors.New("nonsensical libc range given")

// Filter is the userspace counterpart to the `addrfilter` bpf program.
//
// It provides functionality to attach the bpf program to its tracepoint, as well as operations to interact with maps.
//
// Filter doesn't contain any business logic.
type Filter struct {
	logger     *zap.SugaredLogger
	objects    *addrfilterObjects
	tracepoint *link.Link
}

// LoadFilter will load the addrfilter bpf program.
func LoadFilter(logger *zap.SugaredLogger) (*Filter, error) {
	p := &Filter{
		logger:  logger,
		objects: &addrfilterObjects{},
	}

	if err := loadAddrfilterObjects(p.objects, nil); err != nil {
		return nil, fmt.Errorf("failed to load addrfilter objects: %w", err)
	}

	return p, nil
}

// Start attaches the addrfilter program to the raw_tp hook and blocks until the context is cancelled.
func (f *Filter) Start(ctx context.Context) error {
	if err := f.initMaps(); err != nil {
		return fmt.Errorf("failed to initialise maps: %w", err)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: f.objects.addrfilterPrograms.Addrfilter,
	})
	if err != nil {
		return fmt.Errorf("failed to attack to raw tracepoint: %w", err)
	}
	defer tp.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		}
	}
}

// ProtectPID will add a PID to the filter list.
func (f *Filter) ProtectPID(pid int32) error {
	f.logger.Infow("adding process to filter list", "pid", pid)

	if err := f.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}

	return nil
}

// RegisterLibc associates an address mapping with libc for a given process.
//
// addrfilter assumes that libc is one continuous mapping which doesn't change as the program executes
//
// Libc range is used by BPF to identify which return pointers from the stack
// belong to libc. Since the aim is to identify a non-libc syscall site, the
// bpf program will ignore all return pointers in this range.
func (f *Filter) RegisterLibc(pid int32, start, end uint64) error {
	if end <= start {
		return fmt.Errorf("%w: end cannot be less than start", ErrBadLibcRange)
	}

	f.logger.Infow("updating libc address space",
		"pid", pid,
		"start", fmt.Sprintf("0x%x", start),
		"end", fmt.Sprintf("0x%x", end),
	)

	if err := f.objects.LibcRangesMap.Put(
		pid,
		addrfilterVmRange{
			Start:    start,
			End:      end,
			Filename: [256]int8{},
		},
	); err != nil {
		return fmt.Errorf("failed to insert vmrange for pid: %w", err)
	}

	return nil
}

// initMaps will initialise all maps (except the follow map).
func (f *Filter) initMaps() error {
	initFns := []func(*addrfilterObjects) error{
		initStatsMap,
		initStacktraceDebugMap,
	}

	for _, fn := range initFns {
		if err := fn(f.objects); err != nil {
			return fmt.Errorf("failed to initialise map: %w", err)
		}
	}

	return nil
}

// ReadStatsMap will report Stats of execution.
func (f *Filter) ReadStatsMap() (*Stats, error) {
	stats := make([]uint64, addrfilterStatTypeSTAT_END)

	ss := []addrfilterStatType{
		addrfilterStatTypeGET_CUR_TASK_FAILED,
		addrfilterStatTypeTP_ENTERED,
		addrfilterStatTypeIGNORE_PID,
		addrfilterStatTypePID_READ_FAILED,
		addrfilterStatTypeLIBC_NOT_LOADED,
		addrfilterStatTypeGET_STACK_FAILED,
		addrfilterStatTypeCALLSITE_LIBC,
		addrfilterStatTypeSTACK_TOO_SHORT,
		addrfilterStatTypeFILENAME_TOO_LONG,
		addrfilterStatTypeFIND_VMA_FAILED,
		addrfilterStatTypeNO_VMA_BACKING_FILE,
		addrfilterStatTypeWHITELIST_MISSING,
		addrfilterStatTypeSYSCALL_BLOCKED,
		addrfilterStatTypeSEND_SIGNAL_FAILED,
		addrfilterStatTypeSTAT_END,
	}

	for _, s := range ss {
		if err := f.objects.StatsMap.Lookup(&s, &stats[s]); err != nil {
			return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
		}
	}

	return &Stats{
		GetCurrentTaskFailed: stats[addrfilterStatTypeGET_CUR_TASK_FAILED],
		TPEntered:            stats[addrfilterStatTypeTP_ENTERED],
		IgnorePID:            stats[addrfilterStatTypeIGNORE_PID],
		ReadPIDFailed:        stats[addrfilterStatTypePID_READ_FAILED],
		LibcNotLoaded:        stats[addrfilterStatTypeLIBC_NOT_LOADED],
		GetStackFailed:       stats[addrfilterStatTypeGET_STACK_FAILED],
		CallsiteLibc:         stats[addrfilterStatTypeCALLSITE_LIBC],
		StackTooShort:        stats[addrfilterStatTypeSTACK_TOO_SHORT],
		FilenameTooLong:      stats[addrfilterStatTypeFILENAME_TOO_LONG],
		FindVMAFailed:        stats[addrfilterStatTypeFIND_VMA_FAILED],
		NoBackingVMA:         stats[addrfilterStatTypeNO_VMA_BACKING_FILE],
		WhitelistMissing:     stats[addrfilterStatTypeWHITELIST_MISSING],
		SyscallBlocked:       stats[addrfilterStatTypeSYSCALL_BLOCKED],
		SendSignalFailed:     stats[addrfilterStatTypeSEND_SIGNAL_FAILED],
	}, nil
}

// ReadLibcMap is a debug function which can be used to dump the output of the libc map
func (f *Filter) ReadLibcMap() map[int32]*addrfilterVmRange {
	libcMap := make(map[int32]*addrfilterVmRange)

	var (
		pid     int32
		vmRange addrfilterVmRange
	)

	bpfLRM := f.objects.LibcRangesMap.Iterate()
	for {
		next := bpfLRM.Next(&pid, &vmRange)

		f.logger.Infow("read from libcRangeMap",
			"pid", pid,
			"start", fmt.Sprintf("0x%x", vmRange.Start),
			"end", fmt.Sprintf("0x%x", vmRange.End),
		)

		if _, ok := libcMap[pid]; ok {
			f.logger.Warnw("duplicate libc entry found in libc map", "pid", pid)
		}
		libcMap[pid] = &addrfilterVmRange{vmRange.Start, vmRange.End, vmRange.Filename}

		if !next {
			break
		}
	}

	return libcMap
}

// ReadStacktraceMap is a debug function which can be used to dump the output of the libc map
func (f *Filter) ReadStacktraceMap() (*Stacktrace, error) {
	var trace addrfilterStackTraceT

	if err := f.objects.StackDbgMap.Lookup(new(int32), &trace); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			f.logger.Infow("empty debug map")
			return &Stacktrace{}, nil
		}
		return nil, fmt.Errorf("failed to read from stack dbg map: %w", err)
	}

	f.logger.Infow("stacktrace debug",
		"callsite", trace.Callsite,
		"frames walked", trace.FramesWalked,
		"stacktrace", trace.Stacktrace,
	)

	return &Stacktrace{
		Stack:        trace.Stacktrace,
		FramesWalked: trace.FramesWalked,
		CallSite:     trace.Callsite,
	}, nil
}
