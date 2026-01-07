package loader

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Config struct {
	ObjectPath string
	Category   string
	Name       string
	Program    string
	Map        string
}

type App struct {
	ProgramName string
	MapName     string
	coll        *ebpf.Collection
	lnk         link.Link
	m           *ebpf.Map
}

func Start(ctx context.Context, cfg Config) (*App, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	prog := coll.Programs[cfg.Program]
	if prog == nil {
		_ = coll.Close()
		return nil, fmt.Errorf("program not found: %s", cfg.Program)
	}

	m := coll.Maps[cfg.Map]
	if m == nil {
		_ = coll.Close()
		return nil, fmt.Errorf("map not found: %s", cfg.Map)
	}

	lnk, err := link.Tracepoint(cfg.Category, cfg.Name, prog, nil)
	if err != nil {
		_ = coll.Close()
		return nil, fmt.Errorf("attach tracepoint %s/%s: %w", cfg.Category, cfg.Name, err)
	}

	return &App{
		ProgramName: cfg.Program,
		MapName:     cfg.Map,
		coll:        coll,
		lnk:         lnk,
		m:           m,
	}, nil
}

func (a *App) Close() error {
	if a.lnk != nil {
		_ = a.lnk.Close()
	}
	if a.coll != nil {
		return a.coll.Close()
	}
	return nil
}
