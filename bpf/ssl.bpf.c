#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 4096

struct ssl_args {
    __u64 ssl;
    __u64 buf;
    __u64 len;
};

struct ssl_event {
    __u32 pid;
    __u32 tid;

    __u64 timestamp_ns;
    __u64 ssl;

    __u32 requested_len;
    __u32 ret_len;

    char data[MAX_DATA_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_args);
} active_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");


SEC("uprobe/SSL_read")
int ssl_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct ssl_args args = {};

    /*
     * SSL_read(
     *     SSL *ssl,    // arg 1
     *     void *buf,   // arg 2
     *     int num      // arg 3
     * )
     */

    args.ssl = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (__u64)PT_REGS_PARM2(ctx);
    args.len = (__u64)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(
        &active_args,
        &tid,
        &args,
        BPF_ANY
    );

    return 0;
}

SEC("uretprobe/SSL_read")
int ssl_read_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct ssl_args *args;

    args = bpf_map_lookup_elem(
        &active_args,
        &tid
    );

    if (!args)
        return 0;

    __s32 ret = (__s32)PT_REGS_RC(ctx);

    bpf_printk(
        "SSL_read return: ssl=%llx requested=%llu ret=%d",
        args->ssl,
        args->len,
        ret
    );

    /*
     * SSL_read() gagal / retry / EOF.
     * Jangan membuat event.
     */
    if (ret <= 0)
        goto cleanup;

    struct ssl_event *event;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        goto cleanup;

    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl = args->ssl;
    event->requested_len = (__u32)args->len;
    event->ret_len = ret;

    __u32 read_len = (__u32)ret;

    if (read_len > MAX_DATA_SIZE)
        read_len = MAX_DATA_SIZE;

    int err = bpf_probe_read_user(
        event->data,
        read_len,
        (const void *)args->buf
    );

    if (err != 0) {
        bpf_ringbuf_discard(event, 0);
        goto cleanup;
    }

    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(
        &active_args,
        &tid
    );

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
