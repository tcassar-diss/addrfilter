package filter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/tcassar-diss/addrfilter/bpf"
	"go.uber.org/zap"
)

// FilterCfg configures addrfilter's behaviour.
// warnmode will determine addrfilter's behaviour if a process trips the syscall
// filter.
// Profiling information will be written to the profWriter (when it's not nil)
type FilterCfg struct {
	WarnMode   WarnMode
	ProfWriter io.Writer // profWriter can be nil where no profiling is wanted
}

// Filter is a golang interface to the filtering bpf program.
//
// Using Filter takes three steps: first, calling NewFilter
// produces a Filter instance and does the bpf setup behind the scenes.
// Calling Filter.Start() will attack the filtering program to the tracepoint.
// Then, to filter a program, use Filter.ProtectPID().
type Filter struct {
	logger     *zap.SugaredLogger
	libcRange  addrfilterVmRange
	whitelists []*bpf.Whitelist
	cfg        *FilterCfg
	profiler   *Profiler
	tracepoint *link.Link
	objects    *addrfilterObjects
}

// DefaultFilterCfg is the default config: killPID and no profiling
func DefaultFilterCfg() *FilterCfg {
	return &FilterCfg{
		WarnMode:   KillPID,
		ProfWriter: nil,
	}
}

// NewFilter initialises a new filter.
func NewFilter(
	logger *zap.SugaredLogger,
	libcRange *bpf.LibcRange,
	whitelists []*bpf.Whitelist,
	cfg *FilterCfg,
) (*Filter, error) {
	f := &Filter{
		logger: logger,
		libcRange: addrfilterVmRange{
			Start: libcRange.Start,
			End:   libcRange.End,
		},
		whitelists: whitelists,
		cfg:        cfg,
		objects:    &addrfilterObjects{},
	}

	if err := f.init(); err != nil {
		return nil, fmt.Errorf("failed to initialise filter: %w", err)
	}

	return f, nil
}

// Start attaches the BPF filter program to the tracepoint, therefore
// *activating* the filtering. After calling start, register PIDs you want to
// protect with Filter.ProtectPID(). Start is blocking!
func (f *Filter) Start(ctx context.Context) error {
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: f.objects.Addrfilter,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to raw tracepoint: %w", err)
	}
	defer tp.Close()

	go func() {
		if err := f.listen(ctx); err != nil {
			f.logger.Warnw("error listening for warnings from kernel space: %w", err)
		}
	}()

	if f.profiler != nil {
		go func() {
			if err := f.profiler.monitor(ctx); err != nil {
				f.logger.Warnw("error listening for profiling information", "err", err)
			}
		}()
	}

	for range ctx.Done() {
	}

	return nil
}

// ProtectPID registers a process ID in the filtering map, therefore applying
// the whitelists to the process.
func (f *Filter) ProtectPID(pid int32) error {
	f.logger.Infow("adding process to filter list", "pid", pid)

	if err := f.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}

	return nil
}

// ReadStatsMap will report Stats of execution.
func (f *Filter) ReadStatsMap() (*Stats, error) {
	// TODO: refactor into common.go
	stats := make([]uint64, addrfilterStatTypeSTAT_END)

	ss := []addrfilterStatType{
		addrfilterStatTypeGET_CUR_TASK_FAILED,
		addrfilterStatTypeTP_ENTERED,
		addrfilterStatTypeGET_PROFILER_FAILED,
		addrfilterStatTypeIGNORE_PID,
		addrfilterStatTypePID_READ_FAILED,
		addrfilterStatTypePPID_READ_FAILED,
		addrfilterStatTypeFOLLOW_FORK_FAILED,
		addrfilterStatTypeLIBC_NOT_LOADED,
		addrfilterStatTypeSTK_DBG_EMPTY,
		addrfilterStatTypeGET_STACK_FAILED,
		addrfilterStatTypeCALLSITE_LIBC,
		addrfilterStatTypeSTACK_TOO_SHORT,
		addrfilterStatTypeNO_RP_MAPPING,
		addrfilterStatTypeRP_NULL_AFTER_MAP,
		addrfilterStatTypeFILENAME_TOO_LONG,
		addrfilterStatTypeFIND_VMA_FAILED,
		addrfilterStatTypeNO_VMA_BACKING_FILE,
		addrfilterStatTypeWHITELIST_MISSING,
		addrfilterStatTypeSYSCALL_BLOCKED,
		addrfilterStatTypeSEND_SIGNAL_FAILED,
		addrfilterStatTypeKILLMODE_CFG_MISSING,
		addrfilterStatTypeWARN_FAILED_RINGBUF_FULL,
	}

	for _, s := range ss {
		if err := f.objects.StatsMap.Lookup(&s, &stats[s]); err != nil {
			return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
		}
	}

	return &Stats{
		GetCurrentTaskFailed:  stats[addrfilterStatTypeGET_CUR_TASK_FAILED],
		TPEntered:             stats[addrfilterStatTypeTP_ENTERED],
		IgnorePID:             stats[addrfilterStatTypeIGNORE_PID],
		GetProfilerFailed:     stats[addrfilterStatTypeGET_PROFILER_FAILED], // only relevant when profiling
		ReadPIDFailed:         stats[addrfilterStatTypePID_READ_FAILED],
		ReadPPIDFailed:        stats[addrfilterStatTypePPID_READ_FAILED],
		FollowForkFailed:      stats[addrfilterStatTypeFOLLOW_FORK_FAILED],
		LibcNotLoaded:         stats[addrfilterStatTypeLIBC_NOT_LOADED],
		StackDebugEmpty:       stats[addrfilterStatTypeSTK_DBG_EMPTY],
		GetStackFailed:        stats[addrfilterStatTypeGET_STACK_FAILED],
		CallsiteLibc:          stats[addrfilterStatTypeCALLSITE_LIBC],
		StackTooShort:         stats[addrfilterStatTypeSTACK_TOO_SHORT],
		NoRPMapping:           stats[addrfilterStatTypeNO_RP_MAPPING],
		RPNullAfterMap:        stats[addrfilterStatTypeRP_NULL_AFTER_MAP],
		FilenameTooLong:       stats[addrfilterStatTypeFILENAME_TOO_LONG],
		FindVMAFailed:         stats[addrfilterStatTypeFIND_VMA_FAILED],
		NoBackingVMA:          stats[addrfilterStatTypeNO_VMA_BACKING_FILE],
		WhitelistMissing:      stats[addrfilterStatTypeWHITELIST_MISSING],
		SyscallBlocked:        stats[addrfilterStatTypeSYSCALL_BLOCKED],
		SendSignalFailed:      stats[addrfilterStatTypeSEND_SIGNAL_FAILED],
		KillmodeCfgMissing:    stats[addrfilterStatTypeKILLMODE_CFG_MISSING],
		WarnFailedRingbufFull: stats[addrfilterStatTypeWARN_FAILED_RINGBUF_FULL],
	}, nil
}

func (f *Filter) listen(ctx context.Context) any {
	rd, err := ringbuf.NewReader(f.objects.WarnBuf)
	if err != nil {
		return fmt.Errorf("failed to get reader to warn ring buffer: %w", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer close(stopper)

	errChan := make(chan error, 16)
	defer close(errChan)

	go func(errChan chan<- error) {
		for {
			record, err := rd.Read() // rd.Read blocks until there is something to read OR the buffer is closed.
			if errors.Is(err, ringbuf.ErrClosed) {
				f.logger.Infow("warn buffer closed, exiting...")
				return
			} else if err != nil {
				errChan <- fmt.Errorf("failed to read from warn ringbuf: %w", err)
			}

			var pid int32

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pid); err != nil {
				errChan <- fmt.Errorf("failed to unmarshall data from warning buffer")
			}

			switch f.cfg.WarnMode {
			case Warn:
				f.warn(pid, 0) // todo: add syscall number to warning
			case KillAll:
				if err := f.killAll(); err != nil {
					errChan <- fmt.Errorf("failed to kill all processes: %w", err)
				}
			}

		}
	}(errChan)

	// listen on another goroutine so this one can busy wait for a ctx done or interrupt signal.
	// if we also listened to the ringbuffer here, problems would ensue.
	//
	// rd.Read blocks until a read happens, or the buffer is closed.
	// thus, if we listened here, we would never go back and check ctx cancelled, interrupt signal.
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-stopper:
			return nil
		case err := <-errChan:
			f.logger.Warnw("error reading from warn buffer", "err", err)
		}
	}
}

func (f *Filter) init() error {
	if err := loadAddrfilterObjects(f.objects, nil); err != nil {
		return fmt.Errorf("failed to load addrfilter objects: %w", err)
	}

	if f.cfg.ProfWriter != nil {
		if err := f.initProf(); err != nil {
			return fmt.Errorf("failed to initialise profiler: %w", err)
		}
	}

	if err := f.initMaps(); err != nil {
		return fmt.Errorf("failed to initialise BPF maps: %w", err)
	}

	if err := f.regKCfg(); err != nil {
		return fmt.Errorf("failed to register config with kernel: %w", err)
	}

	if err := f.regLibc(); err != nil {
		return fmt.Errorf("failed to register libc address: %w", err)
	}

	if err := f.regWhitelists(); err != nil {
		return fmt.Errorf("failed to register whitelists: %w", err)
	}

	return nil
}

func (f *Filter) initProf() error {
	var err error

	f.profiler, err = newProfiler(f.logger, f.objects.ProfileBuf, f.cfg.ProfWriter)
	if err != nil {
		return fmt.Errorf("failed to create profiler: %w", err)
	}

	return nil
}

func (f *Filter) regKCfg() error {
	key := addrfilterConfigTypeKILL_MODE

	var killmode int32

	switch f.cfg.WarnMode {
	case KillPID:
		killmode = int32(addrfilterKillModeKILL_PID)
	case KillAll:
		killmode = int32(addrfilterKillModeKILL_ALL)
	case Warn:
		killmode = int32(addrfilterKillModeWARN)
	default:
		return fmt.Errorf("%w: %s unsupported", ErrCfgInvalid, f.cfg.WarnMode)
	}

	f.logger.Infow("configuring bpf kill mode", "mode", killmode)

	if err := f.objects.CfgMap.Put(&key, &killmode); err != nil {
		return fmt.Errorf("failed to write config to config map: %w", err)
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

func (f *Filter) regWhitelists() error {
	for _, w := range f.whitelists {
		if err := f.registerWhitelist(w); err != nil {
			return fmt.Errorf("failed to register whitelist: %w", err)
		}
	}

	return nil
}

func (f *Filter) registerWhitelist(whitelist *bpf.Whitelist) error {
	var w addrfilterSyscallWhitelist

	name, err := whitelist.MarshalFilename()
	if err != nil {
		return fmt.Errorf("failed to marshal filename to byte array: %w", err)
	}

	err = f.objects.PathWhitelistMap.Lookup(&name, &w)
	if err != nil {
		if w.Bitmap != [58]uint8{} {
			return fmt.Errorf("%w: non-zerod bitmap already exists", bpf.ErrWhitelistAlreadyExists)
		}
	}

	bitmap, err := whitelist.AsBitmap()
	if err != nil {
		return fmt.Errorf("failed to generate bitmap: %w", err)
	}

	if err := f.objects.PathWhitelistMap.Put(&name, &bitmap); err != nil {
		return fmt.Errorf("failed to write whitelist to kernel space: %w", err)
	}

	return nil
}

func (f *Filter) regLibc() error {
	start := f.libcRange.Start
	end := f.libcRange.End

	if end <= start {
		return fmt.Errorf("%w: end cannot be less than start", bpf.ErrBadLibcRange)
	}

	f.logger.Infow("updating libc address space",
		"start", fmt.Sprintf("0x%x", start),
		"end", fmt.Sprintf("0x%x", end),
	)

	if err := f.objects.LibcRangeMap.Put(
		int32(zero),
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

func (f *Filter) killAll() error {
	var pid int32

	bpfPM := f.objects.ProtectMap.Iterate()
	for {
		next := bpfPM.Next(&pid, &pid)
		if err := bpfPM.Err(); err != nil {
			return fmt.Errorf("failed to read from protect map: %w", err)
		}

		if !next {
			break
		}

		p, err := os.FindProcess(int(pid))
		if err != nil {
			f.logger.Warnw("couldn't find process", "pid", pid, "err", err)

			continue
		}

		if err := p.Kill(); err != nil {
			f.logger.Warnw("couldn't kill process", "pid", pid, "err", err)
		}

	}

	return nil
}

func (f *Filter) warn(pid int32, syscallNr uint64) {
	f.logger.Warnw("blacklisted syscall detected", "pid", pid, "syscall-number", syscallNr)
}
