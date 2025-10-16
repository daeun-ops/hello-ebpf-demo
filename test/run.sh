#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

bash scripts/gen_vmlinux_h.sh
make
sudo ./hello-ebpf-loader
