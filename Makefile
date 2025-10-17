BPF_CLANG ?= clang
GO        ?= go

CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

LOADER_DIR := ./cmd/loader
RING_DIR   := ./cmd/ring_loader

BPF_HELLO_SRC := bpf/hello.bpf.c
BPF_HELLO_OBJ := bpf/hello.bpf.o
BPF_RING_SRC  := bpf/exec_ring.bpf.c
BPF_RING_OBJ  := bpf/exec_ring.bpf.o

HELLO_BIN := hello-ebpf-loader
RING_BIN  := hello-ebpf-ring

.PHONY: all bpf hello ring fmt vet check clean gen

all: bpf hello ring

gen:
	@if [ ! -f bpf/vmlinux.h ]; then \
		echo "[*] generating vmlinux.h"; \
		bash scripts/gen_vmlinux_h.sh; \
	else \
		echo "[OK] vmlinux.h exists"; \
	fi

bpf: gen $(BPF_HELLO_OBJ) $(BPF_RING_OBJ)

$(BPF_HELLO_OBJ): $(BPF_HELLO_SRC) bpf/vmlinux.h
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@

$(BPF_RING_OBJ): $(BPF_RING_SRC) bpf/vmlinux.h
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@

hello:
	$(GO) build -o $(HELLO_BIN) $(LOADER_DIR)

ring:
	$(GO) build -o $(RING_BIN) $(RING_DIR)

fmt:
	@if [ -n "$$(gofmt -l .)" ]; then gofmt -w .; fi

vet:
	$(GO) vet ./...

check:
	bash scripts/check_prereqs.sh

clean:
	rm -f $(BPF_HELLO_OBJ) $(BPF_RING_OBJ) $(HELLO_BIN) $(RING_BIN)
