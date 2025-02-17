package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 --type stack_trace_t --type syscall_whitelist --type stat_type --type vm_range addrfilter ./addrfilter.bpf.c
