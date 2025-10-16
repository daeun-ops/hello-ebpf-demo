package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type pidKey uint32
type countVal uint64
type taskComm struct {
	Comm [16]byte
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("bpf/hello.bpf.o")
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["tp_sys_enter_execve"]
	if prog == nil {
		log.Fatalf("program not found: tp_sys_enter_execve")
	}

	lnk, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer lnk.Close()

	execCount := coll.Maps["exec_count"]
	if execCount == nil {
		log.Fatalf("map not found: exec_count")
	}
	pidComm := coll.Maps["pid_comm"]
	if pidComm == nil {
		log.Fatalf("map not found: pid_comm")
	}

	fmt.Println("attached tracepoint: syscalls:sys_enter_execve")
	fmt.Println("collecting... press Ctrl+C to stop")

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			dump(execCount, pidComm)
		case <-sigc:
			return
		}
	}
}

func dump(execCount, pidComm *ebpf.Map) {
	it := execCount.Iterate()
	var k pidKey
	var v countVal

	for it.Next(&k, &v) {
		var comm taskComm
		_ = pidComm.Lookup(k, &comm)

		name := bytes.TrimRight(comm.Comm[:], "\x00")
		fmt.Printf("PID=%d  exec_cnt=%d  comm=%s\n", uint32(k), uint64(v), string(name))
	}
	if err := it.Err(); err != nil {
		log.Printf("iterate error: %v", err)
	}
}

func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
