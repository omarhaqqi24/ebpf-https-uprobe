#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 4096
#define MAX_SCAN_SIZE MAX_DATA_SIZE
#define MAX_INSPECT_SIZE (4 * MAX_DATA_SIZE)
#define CONN_STATE_TTL_NS (300ULL * 1000000000ULL)
#define MAX_REQUEST_SIZE 8192
#define MAX_METHOD_LEN 16
#define MAX_URI_LEN 256
#define MAX_VERSION_LEN 16
#define MAX_HEADER_NAME 24
#define MAX_SIG_LEN 24
#define VERDICT_TTL_NS (300ULL * 1000000000ULL)

#define REQUEST_FLAG_UNSUPPORTED  (1U << 0)
#define REQUEST_FLAG_MALFORMED    (1U << 1)
#define REQUEST_FLAG_OVERSIZE     (1U << 2)
#define REQUEST_FLAG_CAPTURE_TRUNCATED (1U << 3)
#define REQUEST_FLAG_METADATA_TRUNCATED (1U << 4)
#define REQUEST_FLAG_TRACKING_LOST (1U << 5)

enum parser_mode {
    PARSER_REQUEST_LINE = 0,
    PARSER_HEADERS = 1,
    PARSER_BODY = 2,
    PARSER_DISABLED = 3,
};

enum correlation_status {
    CORRELATION_RELIABLE = 0,
    CORRELATION_UNKNOWN = 1,
};

enum inspection_status {
    INSPECTION_COMPLETE = 0,
    INSPECTION_STOPPED_AFTER_MATCH = 1,
    INSPECTION_INCOMPLETE = 2,
};

enum tracking_status {
    TRACKING_INCOMPLETE = 0,
    TRACKING_COMPLETE = 1,
};

enum verdict_status {
    VERDICT_PENDING = 0,
    VERDICT_CLEAN = 1,
    VERDICT_MALICIOUS = 2,
    VERDICT_INCOMPLETE = 3,
};

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
    __u32 signature_flags;
    __u32 connection_flags;
    __u32 matched_rules;
    __u64 request_sequence;
    __u32 first_signature;
    __u32 correlation_status;
    __u32 is_malicious;
    __u32 flags;
    __u32 read_offset;
    __u32 pad_end;
};

/* Emitted once per complete HTTP/1.1 request, or once for a parser diagnostic. */
struct request_event {
    __u32 tgid;
    __u32 request_length;
    __u64 ssl;
    __u64 request_sequence;
    __u64 timestamp_ns;
    __u16 method_length;
    __u16 uri_length;
    __u16 http_version_length;
    __u16 flags;
    __u32 signature_flags;
    __u32 matched_rules;
    __u32 is_malicious;
    __u32 first_signature;
    __u32 correlation_status;
    __u32 inspection_status;
    __u32 tracking_status;
    char method[MAX_METHOD_LEN];
    char uri[MAX_URI_LEN];
    char http_version[MAX_VERSION_LEN];
    __u32 pad_end;
};

struct request_counters {
    __u64 identified;
    __u64 parser_errors;
    __u64 unsupported;
    __u64 oversized;
    __u64 capture_truncated;
    __u64 ringbuf_drops;
    __u64 detection_drops;
    __u64 unattributed_detections;
    __u64 verdict_updates;
    __u64 verdict_update_failures;
};

struct verdict_key {
    __u32 tgid;
    __u32 pad;
    __u64 ssl;
    __u64 request_sequence;
};

struct verdict_value {
    __u32 status;
    __u32 first_signature;
    __u64 updated_ns;
    __u64 expires_ns;
    __u32 correlation_status;
    __u32 inspection_status;
    __u32 tracking_status;
    __u32 flags;
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
    /* Incremental HTTP/1.1 parser state, scoped to this SSL object. */
    __u64 request_sequence;
    __u64 active_request_sequence;
    __u32 parser_mode;
    __u32 request_length;
    __u32 body_remaining;
    __u32 line_len;
    __u32 header_name_len;
    __u8 saw_cr;
    __u8 has_content_length;
    __u8 parser_error_reported;
    __u8 request_token;
    __u8 header_in_value;
    __u8 header_kind;
    __u8 content_length_digits;
    __u8 content_length_trailing_space;
    __u8 request_started;
    __u8 inspection_done;
    __u8 is_malicious;
    __u8 correlation_known;
    __u16 method_len;
    __u16 uri_len;
    __u16 version_len;
    __u16 request_flags;
    __u16 reported_flags;
    __u16 pad_lengths;
    __u32 first_signature;
    __u32 request_scan_window_len;
    char request_scan_window[MAX_SIG_LEN];
    char header_name[MAX_HEADER_NAME];
    char method[MAX_METHOD_LEN];
    char uri[MAX_URI_LEN];
    char http_version[MAX_VERSION_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct ssl_args);
} active_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} request_events SEC(".maps");

/* Shared with the Nginx module; values contain verdict metadata only. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct verdict_key);
    __type(value, struct verdict_value);
} request_verdicts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct request_counters);
} request_counters_map SEC(".maps");

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

/* Zero-initialized template avoids putting the enlarged state on BPF stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct conn_state);
} conn_state_template SEC(".maps");

static __always_inline char lower_ascii(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static __always_inline int line_equals(const char *line, __u32 len,
                                       const char *literal, __u32 literal_len)
{
    if (len != literal_len)
        return 0;
#pragma unroll
    for (int i = 0; i < 24; i++) {
        if ((__u32)i >= literal_len)
            break;
        if (lower_ascii(line[i]) != literal[i])
            return 0;
    }
    return 1;
}

struct parser_ctx {
    struct conn_state *state;
    struct scan_buffer *scratch;
    __u32 tgid;
    __u32 read_len;
    __u32 read_signature_flags;
    __u32 read_matched_rules;
    __u32 requested_len;
    __s32 ret_len;
    __u32 read_offset;
    __u8 degraded_match_done;
    __u64 ssl;
    __u64 timestamp_ns;
};

static __always_inline struct request_counters *get_request_counters(void);
static __always_inline int update_request_verdict(struct parser_ctx *ctx,
                                                   __u32 status,
                                                   __u32 correlation,
                                                   __u32 inspection,
                                                   __u32 tracking);

#define REQUEST_SUFFIX_MATCH(literal) \
({ \
    int matched = 0; \
    const __u32 plen = sizeof(literal) - 1; \
    if (state->request_scan_window_len >= plen) { \
        matched = 1; \
        _Pragma("unroll") \
        for (int j = 0; j < sizeof(literal) - 1; j++) { \
            if (state->request_scan_window[MAX_SIG_LEN - plen + j] != (literal)[j]) { \
                matched = 0; \
                break; \
            } \
        } \
    } \
    matched; \
})

static __always_inline void emit_detection(struct parser_ctx *ctx, __u32 sig,
                                           __u32 correlated)
{
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        struct request_counters *counters = get_request_counters();
        if (counters)
            counters->detection_drops++;
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->pid = ctx->tgid;
    event->tid = (__u32)bpf_get_current_pid_tgid();
    event->timestamp_ns = ctx->timestamp_ns;
    event->ssl = ctx->ssl;
    event->requested_len = ctx->requested_len;
    event->ret_len = ctx->ret_len;
    event->scanned_len = ctx->read_len;
    event->signature_flags = sig;
    event->request_sequence = correlated ? ctx->state->active_request_sequence : 0;
    event->first_signature = sig;
    event->correlation_status = correlated ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN;
    event->is_malicious = 1;
    event->flags = ctx->state->request_flags;
    event->read_offset = ctx->read_offset;
    bpf_ringbuf_submit(event, 0);
    if (!correlated) {
        struct request_counters *counters = get_request_counters();
        if (counters)
            counters->unattributed_detections++;
    }
}

static __always_inline void inspect_request_byte(struct parser_ctx *ctx, char c)
{
    struct conn_state *state = ctx->state;
    __u32 signature = 0;

    if (state->parser_mode != PARSER_DISABLED && state->inspection_done)
        return;
    /* Without a trustworthy boundary, report at most one unattributed match
     * per SSL_read() result. The next result starts scanning again. */
    if ((state->parser_mode == PARSER_DISABLED || !state->request_started) &&
        ctx->degraded_match_done)
        return;

#pragma unroll
    for (int i = 0; i < MAX_SIG_LEN - 1; i++)
        state->request_scan_window[i] = state->request_scan_window[i + 1];
    state->request_scan_window[MAX_SIG_LEN - 1] = c;
    if (state->request_scan_window_len < MAX_SIG_LEN)
        state->request_scan_window_len++;

    static const char sig_php[] = "text/x-php";
    static const char sig_embed[] = "<embed";
    static const char sig_base64_dq[] = "encoding=\"base64\"";
    static const char sig_base64_sq[] = "encoding='base64'";
    // static const char sig_file_name[] = "<file_name>";
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

    if (!signature && c == 'p' && REQUEST_SUFFIX_MATCH(sig_php)) signature = SIG_TEXT_X_PHP;
    if (!signature && c == 'd' && REQUEST_SUFFIX_MATCH(sig_embed)) signature = SIG_EMBED_TAG;
    if (!signature && c == '"' && REQUEST_SUFFIX_MATCH(sig_base64_dq)) signature = SIG_BASE64_ATTR_DQ;
    if (!signature && c == '\'' && REQUEST_SUFFIX_MATCH(sig_base64_sq)) signature = SIG_BASE64_ATTR_SQ;
    // if (!signature && c == '>' && REQUEST_SUFFIX_MATCH(sig_file_name)) signature = SIG_FILE_NAME_TAG;
    if (!signature && c == '/' && REQUEST_SUFFIX_MATCH(sig_trav_raw)) signature = SIG_TRAVERSAL_RAW;
    if (!signature && c == '\\' && REQUEST_SUFFIX_MATCH(sig_trav_backslash)) signature = SIG_TRAVERSAL_RAW;
    if (!signature && c == '/' && REQUEST_SUFFIX_MATCH(sig_trav_dec_dot_raw_slash)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == ';' && REQUEST_SUFFIX_MATCH(sig_trav_dec_dot_entity_slash)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == '/' && REQUEST_SUFFIX_MATCH(sig_trav_hex_dot_raw_slash)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == ';' && REQUEST_SUFFIX_MATCH(sig_trav_hex_dot_entity_slash)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == ';' && REQUEST_SUFFIX_MATCH(sig_trav_raw_dot_dec_slash)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == ';' && REQUEST_SUFFIX_MATCH(sig_trav_raw_dot_hex_slash)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == ';' && REQUEST_SUFFIX_MATCH(sig_trav_named_entities)) signature = SIG_TRAVERSAL_ENTITY;
    if (!signature && c == ';' && REQUEST_SUFFIX_MATCH(sig_trav_upper_hex)) signature = SIG_TRAVERSAL_ENTITY;

    if (!signature)
        return;

    ctx->read_signature_flags |= signature;
    if (state->parser_mode != PARSER_DISABLED && state->request_started) {
        state->is_malicious = 1;
        state->first_signature = signature;
        state->inspection_done = 1;
        update_request_verdict(ctx, VERDICT_MALICIOUS,
            state->correlation_known ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN,
            INSPECTION_STOPPED_AFTER_MATCH, TRACKING_INCOMPLETE);
        emit_detection(ctx, signature, state->correlation_known);
    } else {
        ctx->degraded_match_done = 1;
        emit_detection(ctx, signature, 0);
    }
}

static __always_inline struct request_counters *get_request_counters(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&request_counters_map, &zero);
}

static __always_inline int update_request_verdict(struct parser_ctx *ctx,
                                                   __u32 status,
                                                   __u32 correlation,
                                                   __u32 inspection,
                                                   __u32 tracking)
{
    if (!ctx->state->request_started ||
        ctx->state->active_request_sequence == 0)
        return -1;

    struct verdict_key key = {
        .tgid = ctx->tgid,
        .pad = 0,
        .ssl = ctx->ssl,
        .request_sequence = ctx->state->active_request_sequence,
    };
    __u64 now = bpf_ktime_get_ns();
    struct verdict_value value = {
        .status = status,
        .first_signature = ctx->state->first_signature,
        .updated_ns = now,
        .expires_ns = now + VERDICT_TTL_NS,
        .correlation_status = correlation,
        .inspection_status = inspection,
        .tracking_status = tracking,
        .flags = ctx->state->request_flags,
    };
    /*
     * Keep the exact sequence entry for diagnostics, plus a per-connection
     * latest slot for Nginx enforcement. Nginx and this parser have separate
     * counters; the parser counter restarts when the detector restarts, while
     * Nginx's keep-alive counter does not. Sequence zero is reserved for the
     * latest slot and is never assigned to a real HTTP request.
     */
    int rc = bpf_map_update_elem(&request_verdicts, &key, &value, BPF_ANY);
    struct verdict_key latest_key = key;
    latest_key.request_sequence = 0;
    int latest_rc = bpf_map_update_elem(&request_verdicts, &latest_key,
                                        &value, BPF_ANY);
    struct request_counters *counters = get_request_counters();
    if (counters) {
        if (rc == 0 && latest_rc == 0)
            counters->verdict_updates++;
        else
            counters->verdict_update_failures++;
    }
    return rc != 0 ? rc : latest_rc;
}

static __always_inline void reset_request(struct conn_state *state)
{
    state->parser_mode = PARSER_REQUEST_LINE;
    state->request_length = 0;
    state->body_remaining = 0;
    state->line_len = 0;
    state->header_name_len = 0;
    state->saw_cr = 0;
    state->has_content_length = 0;
    state->parser_error_reported = 0;
    state->request_token = 0;
    state->header_in_value = 0;
    state->header_kind = 0;
    state->content_length_digits = 0;
    state->content_length_trailing_space = 0;
    state->method_len = 0;
    state->uri_len = 0;
    state->version_len = 0;
    state->active_request_sequence = 0;
    state->request_started = 0;
    state->inspection_done = 0;
    state->is_malicious = 0;
    state->correlation_known = 1;
    state->request_flags = 0;
    state->reported_flags = 0;
    state->first_signature = 0;
    state->request_scan_window_len = 0;
    __builtin_memset(state->request_scan_window, 0, sizeof(state->request_scan_window));
}

static __always_inline int emit_request(struct parser_ctx *ctx, __u16 flags,
                                        __u32 complete)
{
    struct request_event *event;

    event = bpf_ringbuf_reserve(&request_events, sizeof(*event), 0);
    if (!event) {
        struct request_counters *counters = get_request_counters();
        if (counters)
            counters->ringbuf_drops++;
        return -1;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->tgid = ctx->tgid;
    event->request_length = ctx->state->request_length;
    event->ssl = ctx->ssl;
    event->timestamp_ns = ctx->timestamp_ns;
    event->flags = flags;
    event->request_sequence = ctx->state->correlation_known ?
        ctx->state->active_request_sequence : 0;
    event->signature_flags = ctx->state->first_signature;
    event->matched_rules = 0;
    event->is_malicious = ctx->state->is_malicious;
    event->first_signature = ctx->state->first_signature;
    event->correlation_status = ctx->state->correlation_known ?
        CORRELATION_RELIABLE : CORRELATION_UNKNOWN;
    event->inspection_status = ctx->state->is_malicious ?
        INSPECTION_STOPPED_AFTER_MATCH :
        (complete ? INSPECTION_COMPLETE : INSPECTION_INCOMPLETE);
    event->tracking_status = complete ? TRACKING_COMPLETE : TRACKING_INCOMPLETE;

    __u32 method_len = ctx->state->method_len;
    __u32 uri_len = ctx->state->uri_len;
    __u32 version_len = ctx->state->version_len;
    if (method_len > MAX_METHOD_LEN || uri_len > MAX_URI_LEN ||
        version_len > MAX_VERSION_LEN ||
        bpf_probe_read_kernel(event->method, sizeof(event->method),
                              ctx->state->method) != 0 ||
        bpf_probe_read_kernel(event->uri, sizeof(event->uri),
                              ctx->state->uri) != 0 ||
        bpf_probe_read_kernel(event->http_version, sizeof(event->http_version),
                              ctx->state->http_version) != 0) {
        bpf_ringbuf_discard(event, 0);
        struct request_counters *counters = get_request_counters();
        if (counters)
            counters->ringbuf_drops++;
        return -1;
    }
    event->method_length = method_len;
    event->uri_length = uri_len;
    event->http_version_length = version_len;

    if (complete) {
        struct request_counters *counters = get_request_counters();
        if (counters) {
            counters->identified++;
            if (flags & REQUEST_FLAG_OVERSIZE)
                counters->oversized++;
        }
    } else {
        struct request_counters *counters = get_request_counters();
        if (counters) {
            counters->parser_errors++;
            if (flags & REQUEST_FLAG_UNSUPPORTED)
                counters->unsupported++;
            if (flags & REQUEST_FLAG_OVERSIZE)
                counters->oversized++;
            if (flags & REQUEST_FLAG_CAPTURE_TRUNCATED)
                counters->capture_truncated++;
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline void parser_error(struct parser_ctx *ctx, __u16 flags)
{
    ctx->state->request_flags |= flags;
    update_request_verdict(ctx,
        ctx->state->is_malicious ? VERDICT_MALICIOUS : VERDICT_INCOMPLETE,
        ctx->state->correlation_known ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN,
        ctx->state->is_malicious ? INSPECTION_STOPPED_AFTER_MATCH : INSPECTION_INCOMPLETE,
        TRACKING_INCOMPLETE);
    ctx->state->correlation_known = 0;
    if (!ctx->state->parser_error_reported ||
        (ctx->state->request_flags & ~ctx->state->reported_flags)) {
        emit_request(ctx, ctx->state->request_flags, 0);
        ctx->state->reported_flags = ctx->state->request_flags;
        ctx->state->parser_error_reported = 1;
    }
    ctx->state->parser_mode = PARSER_DISABLED;
}

static __always_inline void complete_request(struct parser_ctx *ctx)
{
    update_request_verdict(ctx,
        ctx->state->is_malicious ? VERDICT_MALICIOUS : VERDICT_CLEAN,
        CORRELATION_RELIABLE,
        ctx->state->is_malicious ? INSPECTION_STOPPED_AFTER_MATCH : INSPECTION_COMPLETE,
        TRACKING_COMPLETE);
    if (emit_request(ctx, ctx->state->request_flags, 1) != 0) {
        /* The byte boundary is still known, so preserve synchronization. */
        reset_request(ctx->state);
        return;
    }
    reset_request(ctx->state);
}

static __always_inline int finish_line(struct parser_ctx *ctx)
{
    struct conn_state *state = ctx->state;
    if (state->parser_mode == PARSER_REQUEST_LINE) {
        if (state->request_token != 2 || state->method_len == 0 ||
            state->uri_len == 0 || state->version_len != 8 ||
            state->http_version[0] != 'H' ||
            state->http_version[1] != 'T' ||
            state->http_version[2] != 'T' ||
            state->http_version[3] != 'P' ||
            state->http_version[4] != '/' ||
            state->http_version[5] != '1' ||
            state->http_version[6] != '.' ||
            state->http_version[7] != '1')
            return -1;
        state->correlation_known = 1;
        state->parser_mode = PARSER_HEADERS;
        update_request_verdict(ctx,
            state->is_malicious ? VERDICT_MALICIOUS : VERDICT_PENDING,
            CORRELATION_RELIABLE,
            state->is_malicious ? INSPECTION_STOPPED_AFTER_MATCH : INSPECTION_INCOMPLETE,
            TRACKING_INCOMPLETE);
    } else if (state->parser_mode == PARSER_HEADERS) {
        if (state->line_len == 0) {
            if (state->has_content_length && state->body_remaining > 0) {
                if (state->request_length > MAX_REQUEST_SIZE ||
                    state->body_remaining > MAX_REQUEST_SIZE - state->request_length)
                    state->request_flags |= REQUEST_FLAG_OVERSIZE;
                state->parser_mode = PARSER_BODY;
            } else {
                complete_request(ctx);
            }
        } else {
            if (!state->header_in_value || state->header_name_len == 0)
                return -1;
            if (state->header_kind == 1 && state->content_length_digits == 0)
                return -1;
            state->header_name_len = 0;
            state->header_in_value = 0;
            state->header_kind = 0;
            state->content_length_digits = 0;
            state->content_length_trailing_space = 0;
        }
    }
    state->line_len = 0;
    return 0;
}

static long parse_one_byte(__u32 i, void *opaque)
{
    struct parser_ctx *ctx = opaque;
    struct conn_state *state = ctx->state;
    if (i >= ctx->read_len)
        return 0;
    i &= (MAX_DATA_SIZE - 1);
    char c = ctx->scratch->data[i];

    if (state->parser_mode == PARSER_REQUEST_LINE && !state->request_started &&
        ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
        state->request_sequence++;
        state->active_request_sequence = state->request_sequence;
        state->request_started = 1;
        state->correlation_known = 0;
        update_request_verdict(ctx, VERDICT_PENDING, CORRELATION_UNKNOWN,
                               INSPECTION_INCOMPLETE, TRACKING_INCOMPLETE);
    }
    inspect_request_byte(ctx, c);

    if (state->parser_mode == PARSER_DISABLED)
        return 0;

    if (state->request_length < 0xffffffffU)
        state->request_length++;
    if (state->request_length > MAX_REQUEST_SIZE)
        state->request_flags |= REQUEST_FLAG_OVERSIZE;

    if (state->parser_mode == PARSER_BODY) {
        if (state->body_remaining > 0)
            state->body_remaining--;
        if (state->body_remaining == 0)
            complete_request(ctx);
        return 0;
    }

    if (state->saw_cr) {
        state->saw_cr = 0;
        if (c != '\n') {
            parser_error(ctx, REQUEST_FLAG_MALFORMED);
            return 0;
        }
        int rc = finish_line(ctx);
        if (rc == -2)
            parser_error(ctx, REQUEST_FLAG_UNSUPPORTED);
        else if (rc == -3)
            parser_error(ctx, REQUEST_FLAG_OVERSIZE);
        else if (rc != 0)
            parser_error(ctx, REQUEST_FLAG_MALFORMED);
        return 0;
    }

    if (c == '\r') {
        state->saw_cr = 1;
        return 0;
    }
    if (c == '\n') {
        parser_error(ctx, REQUEST_FLAG_MALFORMED);
        return 0;
    }

    if (state->line_len < 0xffffffffU)
        state->line_len++;
    if (state->parser_mode == PARSER_REQUEST_LINE) {
        if (c == ' ') {
            if (state->request_token == 0 && state->method_len > 0)
                state->request_token = 1;
            else if (state->request_token == 1 && state->uri_len > 0)
                state->request_token = 2;
            else
                parser_error(ctx, REQUEST_FLAG_MALFORMED);
            return 0;
        }

        if (state->request_token == 0) {
            __u32 pos = state->method_len;
            if (pos >= MAX_METHOD_LEN) {
                state->request_flags |= REQUEST_FLAG_METADATA_TRUNCATED;
            } else {
                state->method[pos] = c;
                state->method_len = pos + 1;
            }
        } else if (state->request_token == 1) {
            __u32 pos = state->uri_len;
            if (pos >= MAX_URI_LEN) {
                state->request_flags |= REQUEST_FLAG_METADATA_TRUNCATED;
            } else {
                state->uri[pos] = c;
                state->uri_len = pos + 1;
            }
        } else if (state->request_token == 2) {
            __u32 pos = state->version_len;
            if (pos >= MAX_VERSION_LEN) {
                parser_error(ctx, REQUEST_FLAG_MALFORMED);
                return 0;
            }
            state->http_version[pos] = c;
            state->version_len = pos + 1;
        } else {
            parser_error(ctx, REQUEST_FLAG_MALFORMED);
        }
        return 0;
    }

    if (!state->header_in_value) {
        if (c == ':') {
            if (state->header_name_len == 0) {
                parser_error(ctx, REQUEST_FLAG_MALFORMED);
                return 0;
            }
            state->header_in_value = 1;
            if (line_equals(state->header_name, state->header_name_len,
                            "transfer-encoding", 17)) {
                parser_error(ctx, REQUEST_FLAG_UNSUPPORTED);
                return 0;
            }
            if (line_equals(state->header_name, state->header_name_len,
                            "content-length", 14)) {
                if (state->has_content_length) {
                    parser_error(ctx, REQUEST_FLAG_MALFORMED);
                    return 0;
                }
                state->has_content_length = 1;
                state->header_kind = 1;
            }
            return 0;
        }

        __u32 pos = state->header_name_len;
        if (pos < MAX_HEADER_NAME)
            state->header_name[pos] = lower_ascii(c);
        state->header_name_len = pos + 1;
        return 0;
    }

    if (state->header_kind == 1) {
        if (c == ' ' || c == '\t') {
            if (state->content_length_digits > 0)
                state->content_length_trailing_space = 1;
            return 0;
        }
        if (c < '0' || c > '9' || state->content_length_trailing_space) {
            parser_error(ctx, REQUEST_FLAG_MALFORMED);
            return 0;
        }
        __u32 digit = c - '0';
        if (state->body_remaining > (0xffffffffU - digit) / 10) {
            parser_error(ctx, REQUEST_FLAG_OVERSIZE);
            return 0;
        }
        state->body_remaining = state->body_remaining * 10 + digit;
        if (state->body_remaining > MAX_REQUEST_SIZE)
            state->request_flags |= REQUEST_FLAG_OVERSIZE;
        state->content_length_digits++;
    }
    return 0;
}

SEC("uprobe/SSL_read")
int ssl_read_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ssl_args args = {};
    args.ssl = (__u64)PT_REGS_PARM1(ctx);
    args.buf = (__u64)PT_REGS_PARM2(ctx);
    args.len = (__u64)PT_REGS_PARM3(ctx);

    bpf_map_update_elem(&active_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int ssl_read_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct ssl_args *args = bpf_map_lookup_elem(&active_args, &pid_tgid);
    if (!args)
        return 0;

    __s32 ret = (__s32)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    __u32 returned_len = (__u32)ret;
    __u32 safe_len = returned_len;
    __u16 capture_flags = 0;
    if ((__u64)returned_len > args->len) {
        safe_len = args->len > 0xffffffffULL ? 0xffffffffU : (__u32)args->len;
        capture_flags |= REQUEST_FLAG_CAPTURE_TRUNCATED;
    }
    if (safe_len > MAX_INSPECT_SIZE) {
        safe_len = MAX_INSPECT_SIZE;
        capture_flags |= REQUEST_FLAG_CAPTURE_TRUNCATED;
    }

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
        struct conn_state *initial = bpf_map_lookup_elem(&conn_state_template, &zero);
        if (!initial)
            goto cleanup;
        reset_request(initial);
        initial->last_seen_ns = now;
        bpf_map_update_elem(&conn_states, &key, initial, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&conn_states, &key);
    }
    if (!state)
        goto cleanup;

    struct parser_ctx parser = {
        .state = state,
        .scratch = scratch,
        .tgid = pid,
        .requested_len = args->len > 0xffffffffULL ? 0xffffffffU : (__u32)args->len,
        .ret_len = ret,
        .ssl = args->ssl,
        .timestamp_ns = now,
    };

    if (now - state->last_seen_ns > CONN_STATE_TTL_NS) {
        if (state->request_started) {
            state->correlation_known = 0;
            state->request_flags |= REQUEST_FLAG_TRACKING_LOST;
            emit_request(&parser, state->request_flags, 0);
        }
        reset_request(state);
    }

    /* Process up to 16 KiB in four verifier-friendly 4 KiB chunks. */
#pragma unroll
    for (int chunk = 0; chunk < MAX_INSPECT_SIZE / MAX_DATA_SIZE; chunk++) {
        __u32 offset = chunk * MAX_DATA_SIZE;
        if (offset >= safe_len)
            break;
        __u32 chunk_len = safe_len - offset;
        if (chunk_len > MAX_DATA_SIZE)
            chunk_len = MAX_DATA_SIZE;
        __u64 user_addr = args->buf + offset;
        if (bpf_probe_read_user(scratch->data, chunk_len,
                                (const void *)user_addr) != 0) {
            capture_flags |= REQUEST_FLAG_CAPTURE_TRUNCATED;
            break;
        }
        parser.read_len = chunk_len;
        parser.read_offset = offset;
        long parser_result = bpf_loop(chunk_len, parse_one_byte, &parser, 0);
        if (parser_result < 0) {
            capture_flags |= REQUEST_FLAG_CAPTURE_TRUNCATED;
            break;
        }
    }

    if (state->request_started && state->is_malicious &&
        state->parser_mode != PARSER_DISABLED) {
        update_request_verdict(&parser, VERDICT_MALICIOUS,
            state->correlation_known ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN,
            INSPECTION_STOPPED_AFTER_MATCH, TRACKING_INCOMPLETE);
    }
    state->last_seen_ns = now;
    if (capture_flags)
        parser_error(&parser, capture_flags);

cleanup:
    bpf_map_delete_elem(&active_args, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_free")
int ssl_free_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    struct conn_key key = {
        .pid = pid,
        .pad = 0,
        .ssl = ssl,
    };
    bpf_map_delete_elem(&conn_states, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
