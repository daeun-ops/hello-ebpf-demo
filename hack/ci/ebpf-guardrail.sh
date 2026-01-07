#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ! -f "go.mod" ]]; then
  echo "go.mod not found"
  exit 1
fi

if [[ ! -x "$(command -v bpftool)" ]]; then
  echo "bpftool not found"
  exit 1
fi

if [[ ! -x "$(command -v clang)" ]]; then
  echo "clang not found"
  exit 1
fi

if [[ ! -e "/sys/kernel/btf/vmlinux" ]]; then
  echo "/sys/kernel/btf/vmlinux not found"
  exit 1
fi

sudo mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi

bpftool feature probe || true

go test ./...

workdir=".ci-ebpf"
rm -rf "${workdir}"
mkdir -p "${workdir}"

vmlinux_h="${workdir}/vmlinux.h"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${vmlinux_h}"

mapfile -t bpf_sources < <(find . -type f -name "*.bpf.c" -print)

if [[ "${#bpf_sources[@]}" -eq 0 ]]; then
  echo "No *.bpf.c files found"
  exit 1
fi

objs=()
for src in "${bpf_sources[@]}"; do
  base="$(basename "${src}")"
  out="${workdir}/${base%.c}.o"
  clang -O2 -g -target bpf -c "${src}" -o "${out}" -I"${workdir}" -I"$(dirname "${src}")"
  objs+=("${out}")
done

for obj in "${objs[@]}"; do
  name="$(basename "${obj}" .o)"
  pin="/sys/fs/bpf/ci-${name}"
  sudo rm -rf "${pin}" || true
  sudo mkdir -p "${pin}"
  sudo bpftool prog loadall "${obj}" "${pin}"
  sudo rm -rf "${pin}"
done

echo "eBPF guardrail OK"
