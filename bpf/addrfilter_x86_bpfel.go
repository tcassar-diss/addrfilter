// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type addrfilterStackTraceT struct {
	FramesWalked int32
	_            [4]byte
	Callsite     uint64
	Stacktrace   [32]uint64
}

type addrfilterStatType uint32

const (
	addrfilterStatTypeGET_CUR_TASK_FAILED         addrfilterStatType = 0
	addrfilterStatTypeTP_ENTERED                  addrfilterStatType = 1
	addrfilterStatTypeIGNORE_PID                  addrfilterStatType = 2
	addrfilterStatTypeKILL_RINGBUF_RESERVE_FAILED addrfilterStatType = 3
	addrfilterStatTypePID_READ_FAILED             addrfilterStatType = 4
	addrfilterStatTypeLIBC_NOT_LOADED             addrfilterStatType = 5
	addrfilterStatTypeGET_STACK_FAILED            addrfilterStatType = 6
	addrfilterStatTypeCALLSITE_LIBC               addrfilterStatType = 7
	addrfilterStatTypeSTACK_TOO_SHORT             addrfilterStatType = 8
	addrfilterStatTypeNO_RP_MAPPING               addrfilterStatType = 9
	addrfilterStatTypeSTAT_END                    addrfilterStatType = 10
)

type addrfilterVmRange struct {
	Start uint64
	End   uint64
}

// loadAddrfilter returns the embedded CollectionSpec for addrfilter.
func loadAddrfilter() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_AddrfilterBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load addrfilter: %w", err)
	}

	return spec, err
}

// loadAddrfilterObjects loads addrfilter and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*addrfilterObjects
//	*addrfilterPrograms
//	*addrfilterMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadAddrfilterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadAddrfilter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// addrfilterSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type addrfilterSpecs struct {
	addrfilterProgramSpecs
	addrfilterMapSpecs
	addrfilterVariableSpecs
}

// addrfilterProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type addrfilterProgramSpecs struct {
	Addrfilter *ebpf.ProgramSpec `ebpf:"addrfilter"`
}

// addrfilterMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type addrfilterMapSpecs struct {
	KillMap       *ebpf.MapSpec `ebpf:"kill_map"`
	LibcRangesMap *ebpf.MapSpec `ebpf:"libc_ranges_map"`
	ProtectMap    *ebpf.MapSpec `ebpf:"protect_map"`
	StackDbgMap   *ebpf.MapSpec `ebpf:"stack_dbg_map"`
	StatsMap      *ebpf.MapSpec `ebpf:"stats_map"`
}

// addrfilterVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type addrfilterVariableSpecs struct {
	UnusedStDbg    *ebpf.VariableSpec `ebpf:"unused_st_dbg"`
	UnusedStatType *ebpf.VariableSpec `ebpf:"unused_stat_type"`
	UnusedVmRange  *ebpf.VariableSpec `ebpf:"unused_vm_range"`
}

// addrfilterObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadAddrfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type addrfilterObjects struct {
	addrfilterPrograms
	addrfilterMaps
	addrfilterVariables
}

func (o *addrfilterObjects) Close() error {
	return _AddrfilterClose(
		&o.addrfilterPrograms,
		&o.addrfilterMaps,
	)
}

// addrfilterMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadAddrfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type addrfilterMaps struct {
	KillMap       *ebpf.Map `ebpf:"kill_map"`
	LibcRangesMap *ebpf.Map `ebpf:"libc_ranges_map"`
	ProtectMap    *ebpf.Map `ebpf:"protect_map"`
	StackDbgMap   *ebpf.Map `ebpf:"stack_dbg_map"`
	StatsMap      *ebpf.Map `ebpf:"stats_map"`
}

func (m *addrfilterMaps) Close() error {
	return _AddrfilterClose(
		m.KillMap,
		m.LibcRangesMap,
		m.ProtectMap,
		m.StackDbgMap,
		m.StatsMap,
	)
}

// addrfilterVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadAddrfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type addrfilterVariables struct {
	UnusedStDbg    *ebpf.Variable `ebpf:"unused_st_dbg"`
	UnusedStatType *ebpf.Variable `ebpf:"unused_stat_type"`
	UnusedVmRange  *ebpf.Variable `ebpf:"unused_vm_range"`
}

// addrfilterPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadAddrfilterObjects or ebpf.CollectionSpec.LoadAndAssign.
type addrfilterPrograms struct {
	Addrfilter *ebpf.Program `ebpf:"addrfilter"`
}

func (p *addrfilterPrograms) Close() error {
	return _AddrfilterClose(
		p.Addrfilter,
	)
}

func _AddrfilterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed addrfilter_x86_bpfel.o
var _AddrfilterBytes []byte
