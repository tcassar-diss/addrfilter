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
