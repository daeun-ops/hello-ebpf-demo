#!/usr/bin/env bash
set -Eeuo pipefail

OBJ_PATH="${OBJ_PATH:-}"
LOADER_PKG="${LOADER_PKG:-./cmd/hello-ebpf-loader}"
TP_CATEGORY="${TP_CATEGORY:-syscalls}"
TP_NAME="${TP_NAME:-sys_enter_execve}"
INTERVAL="${INTERVAL:-1s}"
TOP="${TOP:-10}"
JSON="${JSON:-true}"
DURATION_SEC="${DURATION_SEC:-5}"

if [[ ! -x "$(command -v go)" ]]; then
  echo "go not found" >&2
  exit 1
fi

if [[ ! -x "$(command -v clang)" ]]; then
  echo "clang not found" >&2
  exit 1
fi

if [[ ! -x "$(command -v bpftool)" ]]; then
  echo "bpftool not found" >&2
  exit 1
fi

if [[ ! -e "/sys/kernel/btf/vmlinux" ]]; then
  echo "/sys/kernel/btf/vmlinux not found" >&2
  exit 1
fi

sudo mkdir -p /sys/fs/bpf
if ! mountpoint -q /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi

workdir=".runtime-ebpf"
rm -rf "${workdir}"
mkdir -p "${workdir}"

vmlinux_h="${workdir}/vmlinux.h"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${vmlinux_h}"

if [[ -z "${OBJ_PATH}" ]]; then
  if [[ -f "bpf/hello.bpf.o" ]]; then
    OBJ_PATH="bpf/hello.bpf.o"
  else
    src="$(find . -type f -name "*.bpf.c" | head -n 1 || true)"
    if [[ -z "${src}" ]]; then
      echo "no *.bpf.c found and OBJ_PATH not set" >&2
      exit 1
    fi
    OBJ_PATH="${workdir}/hello.bpf.o"
    clang -O2 -g -target bpf -c "${src}" -o "${OBJ_PATH}" -I"${workdir}" -I"$(dirname "${src}")"
  fi
fi

loader_bin="${workdir}/hello-ebpf-loader"
go build -o "${loader_bin}" "${LOADER_PKG}"

out="${workdir}/out.jsonl"
rm -f "${out}"

args=( -obj "${OBJ_PATH}" -tp-category "${TP_CATEGORY}" -tp-name "${TP_NAME}" -interval "${INTERVAL}" -top "${TOP}" )
if [[ "${JSON}" == "true" ]]; then
  args+=( -json )
fi

sudo -E "${loader_bin}" "${args[@]}" > "${out}" 2>&1 &
pid="$!"

trap 'sudo kill -TERM "${pid}" >/dev/null 2>&1 || true; wait "${pid}" >/dev/null 2>&1 || true' EXIT

end="$(( $(date +%s) + DURATION_SEC ))"
while [[ "$(date +%s)" -lt "${end}" ]]; do
  true
  /usr/bin/true
  ls >/dev/null 2>&1 || true
done

sudo kill -TERM "${pid}" >/dev/null 2>&1 || true
wait "${pid}" >/dev/null 2>&1 || true

if [[ ! -s "${out}" ]]; then
  echo "loader produced no output" >&2
  exit 1
fi

if [[ "${JSON}" == "true" ]]; then
  if ! grep -q '"top":\[' "${out}"; then
    cat "${out}" >&2
    echo "json output missing top field" >&2
    exit 1
  fi
else
  if ! grep -q 'pid=' "${out}"; then
    cat "${out}" >&2
    echo "human output missing pid entries" >&2
    exit 1
  fi
fi

echo "runtime smoke OK"
