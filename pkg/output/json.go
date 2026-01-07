package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/daeun-ops/hello-ebpf-demo/pkg/loader"
)

type Pair struct {
	PID   uint32 `json:"pid"`
	Count uint64 `json:"count"`
}

type Snapshot struct {
	At       time.Time `json:"at"`
	Category string    `json:"tp_category"`
	Name     string    `json:"tp_name"`
	Program  string    `json:"program"`
	Map      string    `json:"map"`
	Top      []Pair    `json:"top"`
}

func Top(rows []loader.Row, n int) []Pair {
	if n <= 0 {
		n = 10
	}
	if len(rows) < n {
		n = len(rows)
	}
	out := make([]Pair, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Pair{PID: rows[i].PID, Count: rows[i].Count})
	}
	return out
}

func PrintSnapshotJSON(s Snapshot) {
	b, _ := json.Marshal(s)
	fmt.Println(string(b))
}
