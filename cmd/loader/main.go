package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ hookup"
	"github.com/cilium/ebpf/rlimit"
)

type options struct {
	objPath         string
	interval        time.Duration
	topN            int
	mapName         string
	progName        string
	traceCategory   string
	traceName       string
	jsonOutput      bool
	resetAfterRead  bool
	workdir         string
}

type kv struct {
	Pid   uint32 `json:"pid"`
	Count uint64 `json:"count"`
}

func main() {
	opts := parseFlags()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("failed to remove memlock rlimit", "err", err)
	}

	obj := resolveObjPath(opts.workdir, opts.objPath)
	coll, tpLink, statsMap, err := setup(ctx, logger, obj, opts)
	if err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}
	defer func() {
		if tpLink != nil {
			_ = tpLink.Close()
		}
		if coll != nil {
			_ = coll.Close()
		}
	}()

	logger.Info("running", "obj", obj)
	if err := run(ctx, logger, statsMap, opts); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("run failed", "err", err)
		os.Exit(1)
	}
	logger.Info("stopped")
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.objPath, "obj", "./bpf/hello.bpf.o", "path to BPF ELF object")
	flag.DurationVar(&opts.interval, "interval", 2*time.Second, "read interval")
	flag.IntVar(&opts.topN, "top", 20, "top N PIDs to display")
	flag.StringVar(&opts.mapName, "map", "", "map name to read (optional)")
	flag.StringVar(&opts.progName, "prog", "", "program name to attach (optional)")
	flag.StringVar(&opts.traceCategory, "tp-cat", "", "tracepoint category (optional)")
	flag.StringVar(&opts.traceName, "tp-name", "", "tracepoint name (optional)")
	flag.BoolVar(&opts.jsonOutput, "json", false, "output as json")
	flag.BoolVar(&opts.resetAfterRead, "reset", false, "delete entries after read")
	flag.StringVar(&opts.workdir, "workdir", "", "base directory for resolving relative paths (optional)")
	flag.Parse()
	if opts.topN <= 0 {
		opts.topN = 20
	}
	if opts.interval <= 0 {
		opts.interval = 2 * time.Second
	}
	return opts
}

func resolveObjPath(workdir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	base := workdir
	if base == "" {
		if wd, err := os.Getwd(); err == nil {
			base = wd
		}
	}
	return filepath.Clean(filepath.Join(base, p))
}

func setup(ctx context.Context, logger *slog.Logger, objPath string, opts options) (*ebpf.Collection, link.Link, *ebpf.Map, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new collection: %w", err)
	}

	prog, sec, err := selectProgram(spec, coll, opts.progName)
	if err != nil {
		_ = coll.Close()
		return nil, nil, nil, err
	}

	cat, name, err := resolveTracepoint(sec, opts.traceCategory, opts.traceName)
	if err != nil {
		_ = coll.Close()
		return nil, nil, nil, err
	}

	tpLink, err := link.Tracepoint(cat, name, prog, nil)
	if err != nil {
		_ = coll.Close()
		return nil, nil, nil, fmt.Errorf("attach tracepoint %s:%s: %w", cat, name, err)
	}

	m, err := selectStatsMap(spec, coll, opts.mapName)
	if err != nil {
		_ = tpLink.Close()
		_ = coll.Close()
		return nil, nil, nil, err
	}

	logger.Info("attached", "program", prog.String(), "section", sec, "tracepoint", cat+":"+name, "map", m.String())
	return coll, tpLink, m, nil
}

func selectProgram(spec *ebpf.CollectionSpec, coll *ebpf.Collection, forced string) (*ebpf.Program, string, error) {
	if forced != "" {
		p, ok := coll.Programs[forced]
		if !ok || p == nil {
			return nil, "", fmt.Errorf("program not found: %s", forced)
		}
		if ps, ok := spec.Programs[forced]; ok && ps != nil {
			return p, ps.SectionName, nil
		}
		return p, "", nil
	}

	type candidate struct {
		name string
		sec  string
	}
	var cands []candidate
	for name, ps := range spec.Programs {
		if ps == nil {
			continue
		}
		sec := ps.SectionName
		if strings.HasPrefix(sec, "tracepoint/") {
			if p := coll.Programs[name]; p != nil {
				cands = append(cands, candidate{name: name, sec: sec})
			}
		}
	}
	if len(cands) == 0 {
		for name, p := range coll.Programs {
			if p != nil {
				sec := ""
				if ps, ok := spec.Programs[name]; ok && ps != nil {
					sec = ps.SectionName
				}
				return p, sec, nil
			}
		}
		return nil, "", errors.New("no attachable programs found in collection")
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].name < cands[j].name })
	chosen := cands[0]
	return coll.Programs[chosen.name], chosen.sec, nil
}

func resolveTracepoint(section, forcedCat, forcedName string) (string, string, error) {
	if forcedCat != "" && forcedName != "" {
		return forcedCat, forcedName, nil
	}
	if strings.HasPrefix(section, "tracepoint/") {
		rest := strings.TrimPrefix(section, "tracepoint/")
		parts := strings.Split(rest, "/")
		if len(parts) >= 2 {
			return parts[0], parts[1], nil
		}
	}
	if forcedCat != "" || forcedName != "" {
		return "", "", errors.New("both --tp-cat and --tp-name must be set together")
	}
	return "", "", fmt.Errorf("cannot infer tracepoint from section: %q (set --tp-cat/--tp-name)", section)
}

func selectStatsMap(spec *ebpf.CollectionSpec, coll *ebpf.Collection, forced string) (*ebpf.Map, error) {
	if forced != "" {
		m, ok := coll.Maps[forced]
		if !ok || m == nil {
			return nil, fmt.Errorf("map not found: %s", forced)
		}
		return m, nil
	}

	type candidate struct {
		name string
	}
	var cands []candidate
	for name, ms := range spec.Maps {
		if ms == nil {
			continue
		}
		if ms.Type == ebpf.Hash || ms.Type == ebpf.LRUHash || ms.Type == ebpf.PerCPUHash || ms.Type == ebpf.LRUPerCPUHash {
			if m := coll.Maps[name]; m != nil {
				cands = append(cands, candidate{name: name})
			}
		}
	}
	if len(cands) == 0 {
		for name, m := range coll.Maps {
			if m != nil {
				return m, nil
			}
		}
		return nil, errors.New("no maps found in collection")
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].name < cands[j].name })
	return coll.Maps[cands[0].name], nil
}

func run(ctx context.Context, logger *slog.Logger, m *ebpf.Map, opts options) error {
	t := time.NewTicker(opts.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-t.C:
			items, err := readAll(m, opts.resetAfterRead)
			if err != nil {
				logger.Warn("read map failed", "err", err)
				continue
			}
			render(items, opts.topN, opts.jsonOutput)
		}
	}
}

func readAll(m *ebpf.Map, reset bool) ([]kv, error) {
	var out []kv
	it := m.Iterate()
	var k uint32
	var v uint64
	for it.Next(&k, &v) {
		out = append(out, kv{Pid: k, Count: v})
		if reset {
			_ = m.Delete(k)
		}
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Pid < out[j].Pid
		}
		return out[i].Count > out[j].Count
	})
	return out, nil
}

func render(items []kv, topN int, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(items)
		fmt.Println(string(b))
		return
	}
	if len(items) == 0 {
		fmt.Println("no entries")
		return
	}
	if topN > len(items) {
		topN = len(items)
	}
	fmt.Printf("%-10s %-10s\n", "PID", "COUNT")
	for i := 0; i < topN; i++ {
		fmt.Printf("%-10d %-10d\n", items[i].Pid, items[i].Count)
	}
}
