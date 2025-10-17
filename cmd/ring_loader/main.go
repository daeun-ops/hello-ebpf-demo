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
	"github.com/cilium/ebpf/ringbuf"
)

type execEvent struct {
	TsNS uint64
	PID  uint32
	Comm [16]byte
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("bpf/exec_ring.bpf.o")
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["tp_exec"]
	if prog == nil {
		log.Fatalf("program not found: tp_exec")
	}
	lnk, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer lnk.Close()

	events := coll.Maps["events"]
	if events == nil {
		log.Fatalf("map not found: events")
	}
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	fmt.Println("attached ringbuf demo: syscalls:sys_enter_execve")
	fmt.Println("streaming events... Ctrl+C to stop")

	// graceful shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("ringbuf read: %v", err)
				continue
			}
			var e execEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decode: %v", err)
				continue
			}
			ts := time.Unix(0, int64(e.TsNS)).Format(time.RFC3339Nano)
			fmt.Printf("%s PID=%d comm=%s\n", ts, e.PID, bytes.TrimRight(e.Comm[:], "\x00"))
		}
	}()

	<-sigc
}
