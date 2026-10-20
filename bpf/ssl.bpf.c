#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 1024
#define TAIL_SIZE 64
#define MAX_SCAN_SIZE (MAX_DATA_SIZE + TAIL_SIZE)
#define CONN_STATE_TTL_NS (300ULL * 1000000000ULL)
#define MAX_SCAN_BYTES 1024

/* Signature bits: these describe raw byte patterns observed in the supplied PoCs. */
#define SIG_TEXT_X_PHP          (1U << 0)
#define SIG_EMBED_TAG           (1U << 1)
#define SIG_BASE64_ATTR_DQ      (1U << 2)
#define SIG_BASE64_ATTR_SQ      (1U << 3)
#define SIG_FILE_NAME_TAG       (1U << 4)
#define SIG_TRAVERSAL_RAW       (1U << 5)
#define SIG_TRAVERSAL_ENTITY    (1U << 6)

/* Rule bits. */
#define RULE_OJS_FILE_CONTEXT   (1U << 0)
#define RULE_OJS_TRAVERSAL      (1U << 1)
#define RULE_OJS_CVE_COMBO      (1U << 2)

struct scan_ctx {
    __u32 data_len;
    __u32 found;
};

struct ssl_args {
    __u64 ssl;
    __u64 buf;
    __u64 len;
};

/* Metadata-only event: payload bytes stay in kernel space. */
struct ssl_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u64 ssl;
    __u32 requested_len;
    __s32 ret_len;
    __u32 scanned_len;
    __u32 signature_flags; /* indicators newly observed in this SSL_read */
    __u32 connection_flags; /* indicators accumulated for this SSL object */
    __u32 matched_rules; /* rules newly triggered by this event */
};

/* Per-CPU scratch space for inspecting plaintext without shipping it to user space. */
struct scan_buffer {
    char data[MAX_SCAN_SIZE];
};

struct conn_key {
    __u32 pid;
    __u32 pad;
    __u64 ssl;
};

struct conn_state {
    __u64 last_seen_ns;
    __u32 signature_flags;
    __u32 detected_rules;
    __u32 tail_len;
    char tail[TAIL_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_args);
} active_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scan_buffer);
} scan_buffers SEC(".maps");

/* LRU prevents dead SSL objects from filling the map indefinitely. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} conn_states SEC(".maps");

/*
 * Compare one compile-time literal at a known offset. Keeping the literal
 * in the macro means clang emits constant pattern offsets; the verifier does
 * not have to reason about indexing through a pattern pointer passed to a
 * subprogram.
 */

#define MAX_SIG_LEN 24

#define LITERAL_MATCH_AT(data_ptr, data_len, offset, literal) \
({ \
    int matched = 0; \
    const __u32 plen = sizeof(literal) - 1; \
    if ((offset) < (data_len) && \
        plen <= (data_len) - (offset)) { \
        matched = 1; \
        _Pragma("unroll") \
        for (int j = 0; j < sizeof(literal) - 1; j++) { \
            if ((data_ptr)[(offset) + j] != (literal)[j]) { \
                matched = 0; \
                break; \
            } \
        } \
    } \
    matched; \
})

static long scan_one_offset(__u32 i, void *opaque)
{
    struct scan_ctx *scan = opaque;

    __u32 zero = 0;
    struct scan_buffer *scratch =
        bpf_map_lookup_elem(&scan_buffers, &zero);

    if (!scratch)
        return 1;

    if (i >= scan->data_len)
        return 1;

    /* Bound the dynamic offset after helpers, where the verifier can track it. */
    i &= (MAX_SCAN_BYTES - 1);

    const char *data = scratch->data;
    const __u32 len = scan->data_len;
    char c = data[i];

    static const char sig_php[] = "text/x-php";
    static const char sig_embed[] = "<embed";
    static const char sig_base64_dq[] = "encoding=\"base64\"";
    static const char sig_base64_sq[] = "encoding='base64'";
    static const char sig_file_name[] = "<file_name>";

    static const char sig_trav_raw[] = "../";
    static const char sig_trav_backslash[] = "..\\";
    static const char sig_trav_dec_dot_raw_slash[] = "&#46;&#46;/";
    static const char sig_trav_dec_dot_entity_slash[] = "&#46;&#46;&#47;";
    static const char sig_trav_hex_dot_raw_slash[] = "&#x2e;&#x2e;/";
    static const char sig_trav_hex_dot_entity_slash[] = "&#x2e;&#x2e;&#x2f;";
    static const char sig_trav_raw_dot_dec_slash[] = "..&#47;";
    static const char sig_trav_raw_dot_hex_slash[] = "..&#x2f;";
    static const char sig_trav_named_entities[] = "&dot;&dot;&slash;";
    static const char sig_trav_upper_hex[] = "&#x2E;&#x2E;&#x2F;";

    if (c == 't' &&
        !(scan->found & SIG_TEXT_X_PHP) &&
        LITERAL_MATCH_AT(data, len, i, sig_php))
        scan->found |= SIG_TEXT_X_PHP;

    if (c == '<') {
        if (!(scan->found & SIG_EMBED_TAG) &&
            LITERAL_MATCH_AT(data, len, i, sig_embed))
            scan->found |= SIG_EMBED_TAG;

        if (!(scan->found & SIG_FILE_NAME_TAG) &&
            LITERAL_MATCH_AT(data, len, i, sig_file_name))
            scan->found |= SIG_FILE_NAME_TAG;
    }

    if (c == 'e') {
        if (!(scan->found & SIG_BASE64_ATTR_DQ) &&
            LITERAL_MATCH_AT(data, len, i, sig_base64_dq))
            scan->found |= SIG_BASE64_ATTR_DQ;

        if (!(scan->found & SIG_BASE64_ATTR_SQ) &&
            LITERAL_MATCH_AT(data, len, i, sig_base64_sq))
            scan->found |= SIG_BASE64_ATTR_SQ;
    }

    if (c == '.' && !(scan->found & SIG_TRAVERSAL_RAW)) {
        if (LITERAL_MATCH_AT(data, len, i, sig_trav_raw) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_backslash))
            scan->found |= SIG_TRAVERSAL_RAW;
    }

    if (c == '&' && !(scan->found & SIG_TRAVERSAL_ENTITY)) {
        if (LITERAL_MATCH_AT(data, len, i, sig_trav_dec_dot_raw_slash) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_dec_dot_entity_slash) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_hex_dot_raw_slash) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_hex_dot_entity_slash) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_raw_dot_dec_slash) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_raw_dot_hex_slash) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_named_entities) ||
            LITERAL_MATCH_AT(data, len, i, sig_trav_upper_hex))
            scan->found |= SIG_TRAVERSAL_ENTITY;
    }

    return 0;
}

static __always_inline __u32 evaluate_rules(__u32 flags)
{
    __u32 rules = 0;
    __u32 base64_attr = SIG_BASE64_ATTR_DQ | SIG_BASE64_ATTR_SQ;
    __u32 traversal = SIG_TRAVERSAL_RAW | SIG_TRAVERSAL_ENTITY;

    if ((flags & SIG_TEXT_X_PHP) &&
        (flags & SIG_EMBED_TAG) &&
        (flags & base64_attr))
        rules |= RULE_OJS_FILE_CONTEXT;

    if ((flags & SIG_FILE_NAME_TAG) && (flags & traversal))
        rules |= RULE_OJS_TRAVERSAL;

    if ((rules & RULE_OJS_FILE_CONTEXT) &&
        (rules & RULE_OJS_TRAVERSAL))
        rules |= RULE_OJS_CVE_COMBO;

    return rules;
}

SEC("uprobe/SSL_read")
int ssl_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct ssl_args args = {};
    args.ssl = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (__u64)PT_REGS_PARM2(ctx);
    args.len = (__u64)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&active_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int ssl_read_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct ssl_args *args = bpf_map_lookup_elem(&active_args, &tid);
    if (!args)
        return 0;

    __s32 ret = (__s32)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    __u32 read_len = (__u32)ret;
    if ((__u64)read_len > args->len)
        read_len = (__u32)args->len;
    if (read_len > MAX_DATA_SIZE)
        read_len = MAX_DATA_SIZE;
    if (read_len == 0)
        goto cleanup;

    __u32 zero = 0;
    struct scan_buffer *scratch = bpf_map_lookup_elem(&scan_buffers, &zero);
    if (!scratch)
        goto cleanup;

    __u64 now = bpf_ktime_get_ns();
    struct conn_key key = {
        .pid = pid,
        .pad = 0,
        .ssl = args->ssl,
    };
    struct conn_state *state = bpf_map_lookup_elem(&conn_states, &key);
    if (!state) {
        struct conn_state initial = {};
        initial.last_seen_ns = now;
        bpf_map_update_elem(&conn_states, &key, &initial, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&conn_states, &key);
    }
    if (!state)
        goto cleanup;

    if (now - state->last_seen_ns > CONN_STATE_TTL_NS) {
        state->signature_flags = 0;
        state->detected_rules = 0;
        state->tail_len = 0;
    }

    __u32 prefix_len = state->tail_len;
    if (prefix_len > TAIL_SIZE) {
        prefix_len = 0;
        state->tail_len = 0;
    }

    /* Clear the prefix area first so stale per-CPU bytes cannot match rules. */
#pragma unroll
    for (int i = 0; i < TAIL_SIZE; i++)
        scratch->data[i] = 0;

    /* Copy the saved tail into the bounded prefix window. */
    if (prefix_len > 0 &&
        bpf_probe_read_kernel(&scratch->data[TAIL_SIZE - prefix_len],
                              prefix_len, state->tail) != 0)
        goto cleanup;

    /* Put this SSL_read payload at a fixed offset to simplify verifier bounds. */
    if (read_len > MAX_DATA_SIZE || TAIL_SIZE + read_len > MAX_SCAN_SIZE)
        goto cleanup;
    if (bpf_probe_read_user(&scratch->data[TAIL_SIZE], read_len,
                            (const void *)args->buf) != 0)
        goto cleanup;

    __u32 scan_len = TAIL_SIZE + read_len;
    // __u32 found_flags = scan_signatures(scratch->data, scan_len);

    if (scan_len > MAX_SCAN_BYTES)
        scan_len = MAX_SCAN_BYTES;
    
    struct scan_ctx scan = {
        .data_len = scan_len,
        .found = 0,
    };
    
    long scan_result = bpf_loop(
        scan_len,
        scan_one_offset,
        &scan,
        0
    );
    
    if (scan_result < 0)
        goto cleanup;
    
    __u32 found_flags = scan.found;
    
    __u32 new_flags = found_flags & ~state->signature_flags;
    __u32 updated_flags = state->signature_flags | found_flags;
    __u32 all_rules = evaluate_rules(updated_flags);
    __u32 new_rules = all_rules & ~state->detected_rules;

    state->signature_flags = updated_flags;
    state->last_seen_ns = now;

    /* Save the last bytes using bounded helper copies. */
    __u32 combined_len = prefix_len + read_len;
    if (combined_len >= TAIL_SIZE) {
        if (bpf_probe_read_kernel(state->tail, TAIL_SIZE,
                                  &scratch->data[read_len]) != 0)
            goto cleanup;
        state->tail_len = TAIL_SIZE;
    } else {
        __u32 src_start = TAIL_SIZE - prefix_len;
        if (bpf_probe_read_kernel(state->tail, TAIL_SIZE,
                                  &scratch->data[src_start]) != 0)
            goto cleanup;
        state->tail_len = combined_len;
    }

    /* Nothing matched for the first time: emit no event to user space. */
    if (new_flags == 0 && new_rules == 0)
        goto cleanup;

    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        goto cleanup;

    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = now;
    event->ssl = args->ssl;
    event->requested_len = (__u32)args->len;
    event->ret_len = ret;
    event->scanned_len = read_len;
    event->signature_flags = new_flags;
    event->connection_flags = updated_flags;
    event->matched_rules = new_rules;

    bpf_ringbuf_submit(event, 0);
    state->detected_rules |= new_rules;

cleanup:
    bpf_map_delete_elem(&active_args, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
