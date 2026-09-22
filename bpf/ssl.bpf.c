#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct ssl_args {
    __u64 buf;
    __u64 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_args);
} active_args SEC(".maps");


SEC("uprobe/SSL_read")
int ssl_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct ssl_args args = {};

    /*
     * SSL_read(
     *     SSL *ssl,       arg1
     *     void *buf,      arg2
     *     int num         arg3
     * )
     */

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
    __u32 tid = (__u32)pid_tgid;

    struct ssl_args *args;

    args = bpf_map_lookup_elem(
        &active_args,
        &tid
    );

    if (!args) {
        bpf_printk("SSL_read return: args NOT FOUND");
        return 0;
    }

    __s64 ret = (__s64)PT_REGS_RC(ctx);

    bpf_printk(
        "SSL_read return: ret=%lld",
        ret
    );

    if (ret <= 0)
        goto cleanup;

    char data[128] = {};

    int err = bpf_probe_read_user(
        data,
        sizeof(data) - 1,
        (const void *)args->buf
    );

    if (err != 0) {
        bpf_printk(
            "SSL_read: probe_read_user FAILED err=%d",
            err
        );

        goto cleanup;
    }

    data[sizeof(data) - 1] = '\0';

    bpf_printk(
        "SSL_read plaintext: %s",
        data
    );

cleanup:

    bpf_map_delete_elem(
        &active_args,
        &tid
    );

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
