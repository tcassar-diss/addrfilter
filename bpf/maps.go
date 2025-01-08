package bpf

import "fmt"

var zero = uint64(0)

func initStatsMap(m *addrfilterObjects) error {
	for i := int32(0); i < int32(addrfilterStatTypeSTAT_END); i++ {
		if err := m.StatsMap.Put(&i, &zero); err != nil {
			return fmt.Errorf("failed to initialise errmap %d to zero: %w", i, err)
		}
	}

	return nil
}

func initStacktraceDebugMap(m *addrfilterObjects) error {
	if err := m.StackDbgMap.Put(new(int32), &addrfilterStackTraceT{}); err != nil {
		return fmt.Errorf("failed to write empty struct to map: %w", err)
	}

	return nil
}
