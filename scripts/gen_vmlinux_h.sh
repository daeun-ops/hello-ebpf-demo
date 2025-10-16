#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# gen_vmlinux_h.sh
# ---------------------------------------------------------------------------
# 목적:
#   - 커널의 BTF(BPF Type Format) 정보를 이용해 vmlinux.h 헤더 파일을 자동 생성합니다.
#   - 즉, eBPF가 커널 내부 구조체(task_struct, trace_event 등)를 이해할 수 있도록 돕는 파일.
#
# 설명:
#   - 사실상 "커널 해부도"를 추출하는 작업입니다.
#   - 커널에게 “너의 속을 보여줘”라고 하는 느낌의 스크립트입니다.
#
# 실행 전제:
#   - bpftool이 설치되어 있어야 합니다. (sudo apt install bpftool)
#   - 커널이 BTF를 지원해야 합니다. (/sys/kernel/btf/vmlinux 존재)
#   - 리눅스 커널 5.4 이상이면 기본 지원됩니다.
#
# 현타 주의
#   - 이 파일을 만든다고 세상이 변하지는 않습니다.
#   - 하지만 이 파일이 없으면 eBPF는 “커널이 뭔지 ㅁ나는 몰루 ”라며 댕삐짐. 
# ---------------------------------------------------------------------------

set -euo pipefail  # 에러 발생 시 즉시 종료 정의 안 된 변수 사용 금지!! 파이프라인 오류 체크까지 완벽주의 가즈아

out="bpf/vmlinux.h"  # 결과물 경로 지정
mkdir -p bpf         # 혹시라도 bpf 폴더가 없다면 조용히 만들어.....

# BTF 파일이 없으면, 인생처럼 허무하게 에러를 냅니다
if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
  echo "[ERROR] /sys/kernel/btf/vmlinux not found. Please enable BTF or update kernel headers." >&2
  echo "Hint: Maybe your kernel is too old, like my soul on Friday nights."
  echo "Try: sudo apt install linux-headers-\$(uname -r)"
  exit 1
fi

# 이제 진짜로 커널의 영혼을 뺏어요
echo "[*] Generating ${out}"

# bpftool의 힘으로 커널 내부 구조체를 C 코드 형식으로 덤프
# (이 순간, bpftool은 약간의 마법사입니다)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${out}"

# 결과 보고서
echo "[OK] ${out} generated. You’ve just extracted the kernel’s soul."
