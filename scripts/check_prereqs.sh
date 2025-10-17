#!/usr/bin/env bash
set -euo pipefail

ok=true

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[MISSING] $1"
    ok=false
  else
    echo "[OK] $1 -> $(command -v "$1")"
  fi
}

echo "== checking tools =="
need clang
need bpftool
need go

echo "== checking kernel BTF =="
if [[ -e /sys/kernel/btf/vmlinux ]]; then
  echo "[OK] /sys/kernel/btf/vmlinux present"
else
  echo "[MISSING] /sys/kernel/btf/vmlinux"
  echo "Hint: sudo apt install linux-headers-$(uname -r)"
  ok=false
fi

$ok || { echo "Prereqs not satisfied"; exit 1; }
echo "All good 예아 "
