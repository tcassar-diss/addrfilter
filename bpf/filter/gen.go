package filter

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 --type config_type --type profile_info --type kill_mode --type stack_trace_t --type syscall_whitelist --type stat_type --type vm_range addrfilter ./addrfilter.bpf.c
