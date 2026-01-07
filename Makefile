SHELL := /bin/bash

BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
GO ?= go

BPF_SRC := bpf/hello.bpf.c
BPF_OBJ := bpf/hello.bpf.o

BIN_DIR := bin
LOADER_BIN := $(BIN_DIR)/hello-ebpf-loader
LOADER_MAIN := ./cmd/hello-ebpf-loader

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all build bpf go test clean

all: build

build: bpf go

bpf:
	@mkdir -p $(BIN_DIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	$(BPF_LLVM_STRIP) -g $(BPF_OBJ)

go:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "-s -w" -o $(LOADER_BIN) $(LOADER_MAIN)

test:
	$(GO) test ./...

clean:
	rm -rf $(BIN_DIR) $(BPF_OBJ)
