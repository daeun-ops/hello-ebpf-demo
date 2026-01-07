#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} global_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int safe_access(struct trace_event_raw_sys_enter *ctx) {
    u32 idx = 0;
    u64 *val = bpf_map_lookup_elem(&global_count, &idx);
    if (!val)
        return 0;
    *val += 1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
