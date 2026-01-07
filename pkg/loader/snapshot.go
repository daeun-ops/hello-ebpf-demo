package loader

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
)

type Row struct {
	PID   uint32
	Count uint64
}

func (a *App) Snapshot() ([]Row, error) {
	return snapshotMap(a.m)
}

func snapshotMap(m *ebpf.Map) ([]Row, error) {
	it := m.Iterate()
	var k uint32
	var v uint64
	out := make([]Row, 0, 256)
	for it.Next(&k, &v) {
		out = append(out, Row{PID: k, Count: v})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate map: %w", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].PID < out[j].PID
		}
		return out[i].Count > out[j].Count
	})
	return out, nil
}
