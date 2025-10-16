// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* verifier 실패 유발 테ㅛㅡ트 */
SEC("tracepoint/syscalls/sys_enter_execve")
int bad_prog(void *ctx)
{
    __u64 i = 0;
    for (;;) {
        i++;
        if (i == 0xFFFFFFFFFFFFFFFFULL) {
            break;
        }
    }
    return 0;
}
