#!/usr/bin/env bash
set -euo pipefail

out="bpf/vmlinux.h"
mkdir -p bpf

if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
  echo "[ERROR] /sys/kernel/btf/vmlinux not found. Please enable BTF or update kernel headers." >&2
  exit 1
fi

echo "[*] Generating ${out}"
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${out}"
echo "[OK] ${out} generated"
