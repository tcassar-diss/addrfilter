package wlgen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64  --type syscall_whitelist --type vm_range wlgen ./wlgen.bpf.c
