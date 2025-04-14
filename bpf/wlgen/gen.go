package wlgen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64  --type syscall_whitelist wlgen wlgen.bpf.c
