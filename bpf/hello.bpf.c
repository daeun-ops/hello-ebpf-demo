// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* PID별 exec 호출 횟수를 저장하는 HashMap */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // PID
    __type(value, __u64);  // exec count
    __uint(max_entries, 10240);
} exec_count SEC(".maps");

/* PID -> comm(프로세스 이름) 저장 */
struct task_comm {
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct task_comm);
    __uint(max_entries, 10240);
} pid_comm SEC(".maps");

/* tracepoint: syscalls:sys_enter_execve */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(const struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    __u64 *val = bpf_map_lookup_elem(&exec_count, &pid);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&exec_count, &pid, &init, BPF_ANY);
    }

    struct task_comm c = {};
    bpf_get_current_comm(&c.comm, sizeof(c.comm));
    bpf_map_update_elem(&pid_comm, &pid, &c, BPF_ANY);

    return 0;
}
