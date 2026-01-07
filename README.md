# hello-ebpf-demo

이 프로젝트는 eBPF(extended Berkeley Packet Filter)를 이용해 리눅스 커널 내부 이벤트를 추적하고  
Go 로더를 통해 커널 공간과 유저 공간 간 데이터를 교환하는 예제입니다!!
초보자가 시작하기에 최소 완성 eBPF 데모 프로젝트로 이해하심됩니다 , 근데 아직 안끝나서여

A minimal, production-lean eBPF demo that traces `sys_enter_execve` and aggregates per-PID execution counts in a BPF hash map, with a Go loader that loads/attaches the program and prints periodic snapshots.

### Demonstrates

- Kernel-side safety constraints: verifier-friendly program structure and bounded behavior
- User-space lifecycle: deterministic load, attach, observe, detach, cleanup
- Repeatable builds: Make targets for BPF object + Go binary
- CI guardrails: compile checks and optional load/runtime checks

### Envir

- Linux (x86_64 recommended)
- clang/llvm
- libbpf headers and bpftool
- Go 1.22+

On Ubuntu

- `sudo apt-get update`
- `sudo apt-get install -y clang llvm libbpf-dev bpftool linux-tools-common`

Some distros package `bpftool` via `linux-tools-$(uname -r)`.

### How to build  

Build everything:

- `make build`

Run the loader (needs privileges to load/attach BPF):

- `sudo ./bin/hello-ebpf-loader`

Trigger events (in another terminal):

- `true`
- `ls`
- `bash -lc 'echo hi'`

You should see per-PID counters printed periodically.

## Targets

- `make build` builds `bpf/hello.bpf.o` and `bin/hello-ebpf-loader`
- `make bpf` builds the BPF object only
- `make go` builds the Go loader only
- `make test` runs unit tests
- `make clean` cleans outputs

## Archi

- `bpf/hello.bpf.c`  
  Tracepoint program on `syscalls:sys_enter_execve`, increments `exec_count[pid]`.

- `cmd/hello-ebpf-loader/main.go`  
  Loads `bpf/hello.bpf.o`, attaches to tracepoint, periodically reads `exec_count` and prints top entries, handles SIGINT/SIGTERM gracefully.

## Notes

- If loading fails with permission errors, ensure you run with `sudo`.
- If `bpftool` is missing, install the distro package for your kernel.
- If the kernel forbids BPF, check your distro’s lockdown / security settings.

## Safety and scope

This project is intentionally minimal. It is not a full observability agent:
- no ringbuf/perf events
- no PID namespace correlation
- no long-term storage

