package main

import (
	"fmt"
	"github.com/tcassar-diss/addrfilter/bpf"
)

// WarnMode specifies what action the filter should take when a blacklisted syscall is detected.
type WarnMode string

var (
	// KillPID specifies that only the "malicious" PID is killed when a disallowed syscall happens.
	KillPID WarnMode = "kill-pid"
	// KillAll specifies that all PIDs being traced are killed when a disallowed syscall happens.
	KillAll WarnMode = "kill-all"
	// Warn will simply warn userspace when a disallowed syscall happens - nothing is killed.
	Warn WarnMode = "warn"
)

type ProtectCfg struct {
	Action WarnMode
}

// ProtectJob specifies which program to protect, and how to do so.
type ProtectJob struct {
	PID        int32
	Whitelists []*bpf.Whitelist
	Cfg        *ProtectCfg
}

// Register will register a protection job with kernel space as specified. It will:
//
// 1. Find where libc resides (for the PID) and load it into the kernel
// 2. Write whitelists to kernel space
// 3. Register PID in the FollowMap, beginning syscall filtering protection.
func (j *ProtectJob) Register(filter *bpf.Filter) error {
	libcRange, err := FindLibc(fmt.Sprintf("/proc/%d/maps", j.PID))
	if err != nil {
		return fmt.Errorf("failed to find libc range: %w", err)
	}

	if err := filter.RegisterLibc(j.PID, libcRange.Start, libcRange.End); err != nil {
		return fmt.Errorf("failed to register libc address space with BPF: %w", err)
	}

	if err := filter.RegisterWhitelists(j.Whitelists); err != nil {
		return fmt.Errorf("failed to register whitelists: %w", err)
	}

	if err := filter.ProtectPID(j.PID); err != nil {
		return fmt.Errorf("failed to add PID %d to protect map: %w", j.PID, err)
	}

	return nil
}
