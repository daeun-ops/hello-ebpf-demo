#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} exec_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_exec(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 init = 1;
    u64 *val = bpf_map_lookup_elem(&exec_counter, &pid);
    if (val)
        __sync_fetch_and_add(val, 1);
    else
        bpf_map_update_elem(&exec_counter, &pid, &init, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
