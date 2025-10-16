#!/usr/bin/env bash
set -euo pipefail

rm -f bpf/hello.bpf.o hello-ebpf-loader
echo "[OK] cleaned build artifacts"

sudo rm -f /sys/fs/bpf/fail_prog 2>/dev/null || true
