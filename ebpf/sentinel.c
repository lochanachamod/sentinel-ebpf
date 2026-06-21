// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    __u32 uid;
    __u32 type; // 1 = execve, 2 = connect
    char comm[16];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(void *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->type = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(void *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->type = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
