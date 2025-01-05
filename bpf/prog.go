package bpf

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

type Program struct {
	logger     *zap.SugaredLogger
	objects    *addrfilterObjects
	tracepoint *link.Link
}

// LoadProgram will load the addrfilter bpf program.
func LoadProgram(logger *zap.SugaredLogger) (*Program, error) {
	p := &Program{
		logger:  logger,
		objects: &addrfilterObjects{},
	}

	if err := loadAddrfilterObjects(p.objects, nil); err != nil {
		return nil, fmt.Errorf("failed to load addrfilter objects: %w", err)
	}

	return p, nil
}

// Filter starts the filtering mechanism.
func (p *Program) Filter(ctx context.Context, pid int32) error {
	if err := p.initMaps(); err != nil {
		return fmt.Errorf("failed to initialise maps: %w", err)
	}

	if err := p.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: p.objects.addrfilterPrograms.Addrfilter,
	})
	if err != nil {
		return fmt.Errorf("failed to attack to raw tracepoint: %w", err)
	}
	defer tp.Close()

	for {
		select {
		case <-ctx.Done():
			p.logger.Infow("Stopping filtering: context cancelled")
			return nil
		default:
		}
	}
}

// initMaps will initialise all maps (except the follow map).
func (p *Program) initMaps() error {
	initFns := []func(*addrfilterObjects) error{
		initStatsMap,
	}

	for _, fn := range initFns {
		if err := fn(p.objects); err != nil {
			return fmt.Errorf("failed to initialise map: %w", err)
		}
	}

	return nil
}

// protectPID will apply filter to the requested pid.
func (p *Program) protect(pid int32) error {
	if err := p.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}
	return nil
}

// ReadStatsMap will report Stats of execution.
func (p *Program) ReadStatsMap() (*Stats, error) {
	stats := make([]uint64, addrfilterStatTypeSTAT_END)

	ss := []addrfilterStatType{
		addrfilterStatTypeGET_CUR_TASK_FAILED,
		addrfilterStatTypeTP_ENTERED,
		addrfilterStatTypeIGNORE_PID,
	}

	for _, s := range ss {
		if err := p.objects.StatsMap.Lookup(&s, &stats[s]); err != nil {
			return nil, fmt.Errorf("failed to read ringbuf full errors: %w", err)
		}
	}

	return &Stats{
		GetCurrentTaskFailed: stats[addrfilterStatTypeGET_CUR_TASK_FAILED],
		TPEntered:            stats[addrfilterStatTypeTP_ENTERED],
		IgnorePID:            stats[addrfilterStatTypeIGNORE_PID],
	}, nil
}
