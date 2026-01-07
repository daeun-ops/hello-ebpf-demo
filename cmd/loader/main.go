package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type row struct {
	PID   uint32
	Count uint64
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "memlock: %v\n", err)
		os.Exit(1)
	}

	objPath := os.Getenv("BPF_OBJECT")
	if objPath == "" {
		objPath = "bpf/hello.bpf.o"
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load spec: %v\n", err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "new collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	prog := coll.Programs["trace_execve"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "program not found: trace_execve\n")
		os.Exit(1)
	}

	m := coll.Maps["exec_count"]
	if m == nil {
		fmt.Fprintf(os.Stderr, "map not found: exec_count\n")
		os.Exit(1)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attach tracepoint: %v\n", err)
		os.Exit(1)
	}
	defer tp.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := snapshot(m)
			if err != nil {
				fmt.Fprintf(os.Stderr, "snapshot: %v\n", err)
				continue
			}
			printTop(rows, 10)
		}
	}
}

func snapshot(m *ebpf.Map) ([]row, error) {
	it := m.Iterate()
	var k uint32
	var v uint64
	out := make([]row, 0, 128)
	for it.Next(&k, &v) {
		out = append(out, row{PID: k, Count: v})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func printTop(rows []row, n int) {
	if len(rows) == 0 {
		fmt.Println("exec_count: empty")
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].Count > rows[j].Count
	})
	if n > len(rows) {
		n = len(rows)
	}
	fmt.Println("pid,count")
	for i := 0; i < n; i++ {
		fmt.Printf("%d,%d\n", rows[i].PID, rows[i].Count)
	}
}

var _ = errors.New
