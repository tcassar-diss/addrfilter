package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

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

// Start starts filtering, placing any processes that need killing on the kills channel.
func (f *Filter) Start(ctx context.Context, kills chan int32) error {
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

	rd, err := ringbuf.NewReader(f.objects.KillMap)
	if err != nil {
		return fmt.Errorf("failed to get reader to sc_events_map: %w", err)
	}
	defer rd.Close()

	// ringbuf read blocks, so close from up here when context is cancelled.
	go func() {
		for {
			select {
			case <-ctx.Done():
				rd.Close()
				return
			}
		}
	}()

	if err := f.readKills(ctx, rd, kills); err != nil {
		return fmt.Errorf("failed to read from kills map: %w", err)
	}

	return nil
}

func (f *Filter) ProtectPID(pid int32) error {
	f.logger.Infow("Adding process to filter list", "pid", pid)

	if err := f.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
	}

	return nil
}

func (f *Filter) readKills(ctx context.Context, rd *ringbuf.Reader, kills chan<- int32) error {
	defer close(kills)

	var kill int32

	for {
		select {
		case <-ctx.Done():
			f.logger.Infow("context cancelled, exiting")
			return nil
		default:
		}

		record, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			f.logger.Info("ringbuffer closed, exiting...")

			return nil
		} else if err != nil {
			return fmt.Errorf("failed to read from ringbuffer: %w", err)
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &kill); err != nil {
			return fmt.Errorf("failed to parse binary from bpf map: %w", err)
		}

		kills <- kill
	}
}

// initMaps will initialise all maps (except the follow map).
func (f *Filter) initMaps() error {
	initFns := []func(*addrfilterObjects) error{
		initStatsMap,
	}

	for _, fn := range initFns {
		if err := fn(f.objects); err != nil {
			return fmt.Errorf("failed to initialise map: %w", err)
		}
	}

	return nil
}

// protectPID will apply filter to the requested pid.
func (f *Filter) protect(pid int32) error {
	if err := f.objects.ProtectMap.Put(pid, true); err != nil {
		return fmt.Errorf("failed to register pid into follow map: %w", err)
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
		addrfilterStatTypeKILL_RINGBUF_RESERVE_FAILED,
		addrfilterStatTypePID_READ_FAILED,
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
		RingbufReserveFailed: stats[addrfilterStatTypeKILL_RINGBUF_RESERVE_FAILED],
		ReadPIDFailed:        stats[addrfilterStatTypePID_READ_FAILED],
	}, nil
}
