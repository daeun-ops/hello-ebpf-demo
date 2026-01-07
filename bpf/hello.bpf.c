#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    __u64 init = 1;
    __u64 *val = bpf_map_lookup_elem(&exec_count, &pid);
    if (val) {
        __u64 next = *val + 1;
        bpf_map_update_elem(&exec_count, &pid, &next, BPF_ANY);
        return 0;
    }
    bpf_map_update_elem(&exec_count, &pid, &init, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
