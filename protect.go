package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/tcassar-diss/addrfilter/bpf"
	"go.uber.org/zap"
)

// ProtectJob specifies which program to protect, and how to do so.
type ProtectJob struct {
	logger     *zap.SugaredLogger
	PID        int32
	Whitelists []*bpf.Whitelist
	filter     *bpf.Filter
}

func NewProtectJob(
	logger *zap.SugaredLogger,
	pid int32,
	whitelists []*bpf.Whitelist,
	filter *bpf.Filter,
) *ProtectJob {
	return &ProtectJob{
		logger:     logger,
		PID:        pid,
		Whitelists: whitelists,
		filter:     filter,
	}
}

// SRun will start the protection job.
// It blocks until its context in cancelled or something goes wrong.
func (p *ProtectJob) Run(ctx context.Context) error {
	p.logger.Infow("starting protection", "pid", p.PID)

	if err := p.filter.ProtectPID(p.PID); err != nil {
		return fmt.Errorf("failed to protect PID: %w", err)
	}

	if err := p.register(); err != nil {
		return fmt.Errorf("failed to register job with kernel: %w", err)
	}

	p.logger.Infow("program loaded successfully")

	if err := p.launchFilter(ctx); err != nil {
		return err
	}

	return nil
}

// Stats will read what is in the stats map for a given job.
func (p *ProtectJob) Stats() (*bpf.Stats, error) {
	return p.filter.ReadStatsMap()
}

// Register will register a protection job with kernel space as specified. It will:
//
// 1. Find where libc resides (for the PID) and load it into the kernel
// 2. Write whitelists to kernel space
// 3. Register PID in the FollowMap, beginning syscall filtering protection.
func (p *ProtectJob) register() error {
	libcRange, err := FindLibc(fmt.Sprintf("/proc/%d/maps", p.PID))
	if err != nil {
		return fmt.Errorf("failed to find libc range: %w", err)
	}

	if err := p.filter.RegisterLibc(p.PID, libcRange.Start, libcRange.End); err != nil {
		return fmt.Errorf("failed to register libc address space with BPF: %w", err)
	}

	if err := p.filter.RegisterWhitelists(p.Whitelists); err != nil {
		return fmt.Errorf("failed to register whitelists: %w", err)
	}

	if err := p.filter.RegisterCfg(); err != nil {
		return fmt.Errorf("failed to register config: %w", err)
	}

	if err := p.filter.ProtectPID(p.PID); err != nil {
		return fmt.Errorf("failed to add PID %d to protect map: %w", p.PID, err)
	}

	return nil
}

func (p *ProtectJob) launchFilter(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	go func() {
		for {
			select {
			case <-stopper:
				p.logger.Infow("received ctrl-c, exiting")
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := p.filter.Start(ctx); err != nil {
		cancel()
		return fmt.Errorf("error occured while filtering: %w", err)
	}

	return nil
}
