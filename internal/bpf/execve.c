//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ARGS 3
#define ARG_LEN  64

struct event {
    __u32 pid;
    __u64 cgroup_id;
    char  filename[256];
    char  args[MAX_ARGS][ARG_LEN];
};

const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    const char *const *argv = (const char *const *)ctx->args[1];
    #pragma unroll

    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg_ptr = 0;
        long ret = bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]);
        if (ret != 0 || !arg_ptr) {
            e->args[i][0] = '\0';
            break;
        }
        bpf_probe_read_user_str(&e->args[i], sizeof(e->args[i]), arg_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
