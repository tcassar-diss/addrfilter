package bpf

import (
	"fmt"
)

func initStatsMap(m *addrfilterObjects) error {
	zero := uint64(0)

	// this is okay in >=go1.22
	// see https://go.dev/wiki/LoopvarExperiment
	for i := int32(0); i < int32(addrfilterStatTypeSTAT_END); i++ {
		if err := m.StatsMap.Put(&i, &zero); err != nil {
			return fmt.Errorf("failed to initialise errmap %d to zero: %w", i, err)
		}
	}

	return nil
}
