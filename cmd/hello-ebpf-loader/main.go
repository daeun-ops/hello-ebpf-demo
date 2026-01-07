package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daeun-ops/hello-ebpf-demo/pkg/loader"
	"github.com/daeun-ops/hello-ebpf-demo/pkg/output"
)

func main() {
	cfg := parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app, err := loader.Start(ctx, loader.Config{
		ObjectPath: cfg.ObjectPath,
		Category:   cfg.Category,
		Name:       cfg.Name,
		Program:    cfg.Program,
		Map:        cfg.Map,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer app.Close()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := app.Snapshot()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			output.PrintSnapshotJSON(output.Snapshot{
				At:       time.Now().UTC(),
				Category: cfg.Category,
				Name:     cfg.Name,
				Program:  app.ProgramName,
				Map:      app.MapName,
				Top:      output.Top(rows, cfg.TopN),
			})
		}
	}
}

type cfg struct {
	ObjectPath string
	Category   string
	Name       string
	Program    string
	Map        string
	Interval   time.Duration
	TopN       int
}

func parse() cfg {
	var c cfg
	flag.StringVar(&c.ObjectPath, "obj", "bpf/hello.bpf.o", "path to eBPF object")
	flag.StringVar(&c.Category, "tp-category", "syscalls", "tracepoint category")
	flag.StringVar(&c.Name, "tp-name", "sys_enter_execve", "tracepoint name")
	flag.StringVar(&c.Program, "program", "trace_execve", "program name")
	flag.StringVar(&c.Map, "map", "exec_count", "map name")
	flag.DurationVar(&c.Interval, "interval", 2*time.Second, "poll interval")
	flag.IntVar(&c.TopN, "top", 10, "top N")
	flag.Parse()

	if c.TopN <= 0 {
		c.TopN = 10
	}
	if c.Interval <= 0 {
		c.Interval = 2 * time.Second
	}
	return c
}
