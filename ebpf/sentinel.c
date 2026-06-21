// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 type; // 1 = execve, 2 = connect
    char parent_comm[16];
    char filename[64];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Manually define the tracepoint struct for execve to avoid needing vmlinux.h
struct sys_enter_execve_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct sys_enter_execve_args *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->type = 1;
    
    // Get the name of the parent process making the execve call
    bpf_get_current_comm(&e->parent_comm, sizeof(e->parent_comm));
    
    // Read the actual user-space filename being executed
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Manually define the tracepoint struct for connect
struct sys_enter_connect_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int fd;
    struct sockaddr *uservaddr;
    int addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct sys_enter_connect_args *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->type = 2;
    bpf_get_current_comm(&e->parent_comm, sizeof(e->parent_comm));
    
    // For connect, we just clear filename for now since it doesn't apply
    __builtin_memset(&e->filename, 0, sizeof(e->filename));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
