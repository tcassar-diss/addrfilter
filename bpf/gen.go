package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target amd64 --type stat_type addrfilter ./addrfilter.bpf.c
