// Package bpf provides an interface for interacting with the kernelspace components
// of the addrfilter program.
//
// The primary function Filter.Load() loads the BPF program and attaches it to the
// raw_tp/sys_enter tracepoint. This function blocks until its context is canceled.
//
// This package is intended as an interface to kernelspace, without containing specific
// business logic.
package bpf
