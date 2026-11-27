#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 4096
#define MAX_SCAN_SIZE MAX_DATA_SIZE
#define MAX_INSPECT_SIZE (15 * 1024)
#define MAX_PARSE_BATCH 512
#define CONN_STATE_TTL_NS (300ULL * 1000000000ULL)
#define MAX_REQUEST_SIZE 8192
#define MAX_METHOD_LEN 16
#define MAX_URI_LEN 256
#define MAX_VERSION_LEN 16
#define MAX_HEADER_NAME 64
#define MAX_SCOPE_NAME 64
#define MAX_SCOPES 16
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
    PARSER_FORM_BODY = 4,
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

#define MAX_SIGNATURES 32
#define MAX_AUTOMATON_STATES 512
#define MAX_RULES 32

struct signature_pattern {
    __u32 rule_index;
    __u32 verdict_mask;
    __u8 enabled;
    __u8 case_sensitive;
    __u8 pattern_len;
    __u8 pad;
    char pattern[MAX_SIG_LEN];
};
struct automaton_transition {
    __u32 next_state;
    __u32 matched_signatures;
    __u32 matched_rules;
    __u32 verdict_flags;
};
struct rule_config {
    __u32 signature_mask;
    __u8 enabled;
    __u8 pad[3];
};

struct ssl_args {
    __u64 ssl;
    __u64 buf;
    __u64 len;
};
struct conn_key {
    __u32 pid;
    __u32 pad;
    __u64 ssl;
};
struct ssl_read_context {
    struct conn_key key;
    __u32 tgid;
    __s32 ret_len;
    __u32 requested_len;
    __u32 safe_len;
    __u32 capture_flags;
    __u32 chunk_index;
    __u32 expected_chunks;
    __u32 byte_offset;
    __u32 current_chunk_len;
    __u32 pad;
    __u64 timestamp_ns;
    __u64 ssl;
    __u64 read_sequence;
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
    __u32 matched_signatures;
    __u32 correlation_status;
    __u32 inspection_status;
    __u32 tracking_status;
    char method[MAX_METHOD_LEN];
    char uri[MAX_URI_LEN];
    char http_version[MAX_VERSION_LEN];
    __u32 pad_end;
    __u32 pad_end2;
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
    __u64 raw_chunks_submitted;
    __u64 raw_ringbuf_drops;
    __u64 raw_bytes_submitted;
    __u64 raw_capture_truncated;
    __u64 raw_capture_failures;
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


struct scope_key {
    __u32 prefix_len;
    __u8 kind;
    __u8 name_len;
    __u16 pad;
    char name[MAX_SCOPE_NAME];
};
struct conn_state {
    __u64 last_seen_ns;
    __u64 read_sequence;
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
    __u8 content_type_index;
    __u8 content_type_valid;
    __u8 content_type_seen;
    __u8 body_form;
    __u8 body_in_value;
    __u8 scope_active;
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
    __u32 matched_signatures;
    __u32 matched_rules;
    __u32 rule_seen[MAX_RULES];
    __u32 scoped_matcher_state;
    __u32 active_scope_id;
    __u32 exact_matcher_state;
    __u32 folded_matcher_state;
    char request_scan_window[MAX_SIG_LEN];
    struct scope_key header_scope_key;
    struct scope_key body_scope_key;
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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ssl_read_context);
} ssl_read_contexts SEC(".maps");
static __always_inline struct ssl_read_context *get_ssl_read_context(void)
{
    __u32 zero=0;
    return bpf_map_lookup_elem(&ssl_read_contexts,&zero);
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} parser_programs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} request_events SEC(".maps");

struct raw_chunk_event {
    __u32 tgid;
    __u32 tid;
    __u64 ssl;
    __u64 read_sequence;
    __u64 timestamp_ns;
    __u32 read_total_len;
    __u32 read_offset;
    __u32 chunk_index;
    __u32 expected_chunk_count;
    __u32 data_len;
    __u32 flags;
    __u32 event_type; /* 0=chunk, 1=SSL_free */
    char data[MAX_DATA_SIZE];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} raw_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SIGNATURES);
    __type(key, __u32);
    __type(value, struct signature_pattern);
} signature_patterns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct automaton_transition);
} automaton_transitions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SCOPES * MAX_AUTOMATON_STATES * 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct automaton_transition);
} scoped_transitions SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_SCOPES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct scope_key);
    __type(value, __u32);
} scope_registry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rule_config);
} rule_configs SEC(".maps");

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
    __u32 callback_offset;
};

static __always_inline int update_request_verdict(struct parser_ctx *ctx, __u32 status, __u32 correlation, __u32 inspection, __u32 tracking);
static __always_inline void emit_detection(struct parser_ctx *ctx, __u32 sig, __u32 rule_mask, __u32 malicious, __u32 correlated);

static __noinline void inspect_scoped_byte(struct parser_ctx *ctx, __u32 scope_id, char c)
{
    if (!scope_id) return;
    struct conn_state *state=ctx->state;
    __u32 key=(scope_id*MAX_AUTOMATON_STATES+state->scoped_matcher_state)*256+(__u8)c;
    struct automaton_transition *tr=bpf_map_lookup_elem(&scoped_transitions,&key);
    __u32 next=0,matches=0,rules=0,flags=0;
    if(tr){next=tr->next_state;matches=tr->matched_signatures;rules=tr->matched_rules;flags=tr->verdict_flags;}
    state->scoped_matcher_state=next;
    if(!matches)return;
    state->matched_signatures|=matches;
    state->matched_rules|=rules;
    if(!state->first_signature) state->first_signature=flags;
    state->is_malicious=state->matched_rules!=0;
    update_request_verdict(ctx, VERDICT_MALICIOUS,
        state->correlation_known ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN,
        INSPECTION_INCOMPLETE, TRACKING_INCOMPLETE);
    emit_detection(ctx,matches,state->matched_rules,state->is_malicious,state->correlation_known);
}
static __always_inline __u32 lookup_scope(const struct scope_key *key);
static __always_inline void parser_error(struct parser_ctx *ctx, __u16 flags);
static __always_inline void inspect_form_body_byte(struct parser_ctx *ctx, char c)
{
    struct conn_state *state=ctx->state;
    if (!state->body_in_value) {
        if (c == '&') { state->body_scope_key.name_len=0; state->body_scope_key.prefix_len=32; state->body_scope_key.kind=2; state->body_scope_key.pad=0; }
        else if (c == '=') { state->body_in_value=1; state->active_scope_id=state->body_scope_key.name_len ? lookup_scope(&state->body_scope_key) : 0; state->scoped_matcher_state=0; }
        else { __u32 n=state->body_scope_key.name_len; if (n>=MAX_SCOPE_NAME) { parser_error(ctx,REQUEST_FLAG_UNSUPPORTED); return; } if(n==0){state->body_scope_key.kind=2; state->body_scope_key.pad=0;} state->body_scope_key.name[n]=c; state->body_scope_key.name_len=n+1; state->body_scope_key.prefix_len=(4+n+1)*8; }
    } else if (c == '&') { state->body_in_value=0; state->active_scope_id=0; state->scoped_matcher_state=0; state->body_scope_key.name_len=0; state->body_scope_key.prefix_len=32; state->body_scope_key.kind=2; state->body_scope_key.pad=0; }
    else inspect_scoped_byte(ctx,state->active_scope_id,c);
}
static __always_inline __u32 lookup_scope(const struct scope_key *key)
{
    __u32 *id=bpf_map_lookup_elem(&scope_registry,key);
    return id ? *id : 0;
}

static __always_inline struct request_counters *get_request_counters(void);
static __always_inline int update_request_verdict(struct parser_ctx *ctx,
                                                   __u32 status,
                                                   __u32 correlation,
                                                   __u32 inspection,
                                                   __u32 tracking);

static __always_inline void emit_detection(struct parser_ctx *ctx, __u32 sig,
                                           __u32 rule_mask, __u32 malicious,
                                           __u32 correlated)
{
    struct ssl_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        struct request_counters *counters = get_request_counters();
        if (counters)
            counters->detection_drops++;
        return;
    }
    struct ssl_read_context *read_ctx=get_ssl_read_context();
    if(!read_ctx){bpf_ringbuf_discard(event,0);return;}
    event->pid = read_ctx->tgid;
    event->tid = (__u32)bpf_get_current_pid_tgid();
    event->timestamp_ns = read_ctx->timestamp_ns;
    event->ssl = read_ctx->ssl;
    event->requested_len = read_ctx->requested_len;
    event->ret_len = read_ctx->ret_len;
    event->scanned_len = read_ctx->current_chunk_len;
    event->signature_flags = sig;
    event->matched_rules = rule_mask;
    event->request_sequence = (correlated || (ctx->state->parser_mode != PARSER_DISABLED && ctx->state->request_started)) ? ctx->state->active_request_sequence : 0;
    event->first_signature = sig;
    event->correlation_status = correlated ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN;
    event->is_malicious = malicious;
    event->flags = ctx->state->request_flags;
    event->read_offset = read_ctx->chunk_index*MAX_DATA_SIZE+read_ctx->byte_offset;
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
    __u32 key = state->exact_matcher_state * 256 + (__u8)c;
    struct automaton_transition *exact = bpf_map_lookup_elem(&automaton_transitions, &key);
    __u32 exact_next = 0, exact_sigs = 0, exact_rules = 0, exact_flags = 0;
    if (exact) {
        exact_next = exact->next_state;
        exact_sigs = exact->matched_signatures;
        exact_rules = exact->matched_rules;
        exact_flags = exact->verdict_flags;
    }
    state->exact_matcher_state = exact_next;

    __u32 folded_key = (MAX_AUTOMATON_STATES + state->folded_matcher_state) * 256 +
                       (__u8)lower_ascii(c);
    struct automaton_transition *folded = bpf_map_lookup_elem(&automaton_transitions, &folded_key);
    __u32 folded_next = 0, folded_sigs = 0, folded_rules = 0, folded_flags = 0;
    if (folded) {
        folded_next = folded->next_state;
        folded_sigs = folded->matched_signatures;
        folded_rules = folded->matched_rules;
        folded_flags = folded->verdict_flags;
    }
    state->folded_matcher_state = folded_next;

    __u32 matches = exact_sigs | folded_sigs;
    if (!matches)
        return;
    __u32 triggered_rules = exact_rules | folded_rules;
    __u32 verdict_flags = exact_flags | folded_flags;
    if (state->parser_mode != PARSER_DISABLED && state->request_started) {
        state->matched_signatures |= matches;
        if (!state->first_signature)
            state->first_signature = verdict_flags;
        state->matched_rules |= triggered_rules;
        state->is_malicious = state->matched_rules != 0;
        update_request_verdict(ctx, state->is_malicious ? VERDICT_MALICIOUS : VERDICT_PENDING,
            state->correlation_known ? CORRELATION_RELIABLE : CORRELATION_UNKNOWN,
            INSPECTION_INCOMPLETE, TRACKING_INCOMPLETE);
        emit_detection(ctx, matches, state->matched_rules, state->is_malicious,
                       state->correlation_known);
    } else {
        emit_detection(ctx, matches, triggered_rules, triggered_rules != 0, 0);
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

    struct ssl_read_context *read_ctx=get_ssl_read_context();
    if(!read_ctx)return -1;
    struct verdict_key key = {
        .tgid = read_ctx->tgid,
        .pad = 0,
        .ssl = read_ctx->ssl,
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
    state->exact_matcher_state = 0;
    state->folded_matcher_state = 0;
    state->body_remaining = 0;
    state->line_len = 0;
    state->header_name_len = 0;
    state->saw_cr = 0;
    state->has_content_length = 0;
    state->parser_error_reported = 0;
    state->request_token = 0;
    state->header_in_value = 0;
    state->header_kind = 0;
    state->active_scope_id = 0;
    state->scope_active = 0;
    state->content_type_index = 0;
    state->content_type_valid = 0;
    state->content_type_seen = 0;
    state->body_form = 0;
    state->body_in_value = 0;
    state->header_scope_key.name_len=0; state->header_scope_key.prefix_len=32; state->header_scope_key.kind=1; state->header_scope_key.pad=0; state->body_scope_key.name_len=0; state->body_scope_key.prefix_len=32; state->body_scope_key.kind=2; state->body_scope_key.pad=0;
    state->scoped_matcher_state = 0;
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
    state->matched_signatures = 0;
    state->matched_rules = 0;
    __builtin_memset(state->rule_seen, 0, sizeof(state->rule_seen));
    state->scoped_matcher_state = 0;
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

    struct ssl_read_context *read_ctx=get_ssl_read_context();
    if(!read_ctx){bpf_ringbuf_discard(event,0);return -1;}
    event->tgid = read_ctx->tgid;
    event->request_length = ctx->state->request_length;
    event->ssl = read_ctx->ssl;
    event->timestamp_ns = read_ctx->timestamp_ns;
    event->flags = flags;
    event->request_sequence = ctx->state->correlation_known ?
        ctx->state->active_request_sequence : 0;
    event->signature_flags = ctx->state->matched_signatures;
    event->matched_rules = ctx->state->matched_rules;
    event->is_malicious = ctx->state->is_malicious;
    event->first_signature = ctx->state->first_signature;
    event->matched_signatures = ctx->state->matched_signatures;
    event->correlation_status = ctx->state->correlation_known ?
        CORRELATION_RELIABLE : CORRELATION_UNKNOWN;
    event->inspection_status = complete ? INSPECTION_COMPLETE : INSPECTION_INCOMPLETE;
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
        INSPECTION_INCOMPLETE,
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
        INSPECTION_COMPLETE,
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
            INSPECTION_INCOMPLETE,
            TRACKING_INCOMPLETE);
    } else if (state->parser_mode == PARSER_HEADERS) {
        if (state->line_len == 0) {
            if (state->has_content_length && state->body_remaining > 0) {
                if (state->request_length > MAX_REQUEST_SIZE ||
                    state->body_remaining > MAX_REQUEST_SIZE - state->request_length)
                    state->request_flags |= REQUEST_FLAG_OVERSIZE;
                state->parser_mode = state->body_form ? PARSER_FORM_BODY : PARSER_BODY;
            } else {
                complete_request(ctx);
            }
        } else {
            if (!state->header_in_value || state->header_name_len == 0)
                return -1;
            if (state->header_kind == 1 && state->content_length_digits == 0)
                return -1;
            if (state->header_kind == 2) {
                if (state->content_type_seen) { parser_error(ctx, REQUEST_FLAG_MALFORMED); return 0; }
                state->body_form = state->content_type_valid && state->content_type_index >= 33;
                state->content_type_seen = 1;
            }
            state->header_name_len = 0;
            state->header_scope_key.name_len = 0;
            state->header_in_value = 0;
            state->active_scope_id = 0;
            state->scope_active = 0;
            state->scoped_matcher_state = 0;
            state->header_kind = 0;
            state->content_length_digits = 0;
            state->content_length_trailing_space = 0;
        }
    }
    state->line_len = 0;
    return 0;
}

static __always_inline long parse_one_byte_inner(__u32 i, void *opaque);
static long parse_one_byte(__u32 i, void *opaque)
{
    struct parser_ctx *ctx=opaque;
    return parse_one_byte_inner(i+ctx->callback_offset, opaque);
}

static __always_inline void parse_request_line_byte(struct parser_ctx *ctx, char c)
{
    struct conn_state *state=ctx->state;
    if(c==' '){if(state->request_token==0&&state->method_len>0)state->request_token=1;else if(state->request_token==1&&state->uri_len>0)state->request_token=2;else parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}
    if(state->request_token==0){__u32 pos=state->method_len;if(pos>=MAX_METHOD_LEN)state->request_flags|=REQUEST_FLAG_METADATA_TRUNCATED;else{state->method[pos]=c;state->method_len=pos+1;}}
    else if(state->request_token==1){__u32 pos=state->uri_len;if(pos>=MAX_URI_LEN)state->request_flags|=REQUEST_FLAG_METADATA_TRUNCATED;else{state->uri[pos]=c;state->uri_len=pos+1;}}
    else if(state->request_token==2){__u32 pos=state->version_len;if(pos>=MAX_VERSION_LEN){parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}state->http_version[pos]=c;state->version_len=pos+1;}
    else parser_error(ctx,REQUEST_FLAG_MALFORMED);
}

static __always_inline void parse_header_byte(struct parser_ctx *ctx, char c)
{
    struct conn_state *state=ctx->state;
    if(!state->header_in_value){
        if(c==':'){
            if(state->header_name_len==0){parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}
            state->header_in_value=1;state->scoped_matcher_state=0;state->active_scope_id=lookup_scope(&state->header_scope_key);state->scope_active=state->active_scope_id!=0;
            if(line_equals(state->header_scope_key.name,state->header_name_len,"content-type",12)){state->header_kind=2;state->content_type_index=0;state->content_type_valid=1;}
            if(line_equals(state->header_scope_key.name,state->header_name_len,"transfer-encoding",17)){parser_error(ctx,REQUEST_FLAG_UNSUPPORTED);return;}
            if(line_equals(state->header_scope_key.name,state->header_name_len,"content-length",14)){if(state->has_content_length){parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}state->has_content_length=1;state->header_kind=1;}
            return;
        }
        __u32 pos=state->header_name_len;
        if(pos>=MAX_HEADER_NAME){parser_error(ctx,REQUEST_FLAG_UNSUPPORTED);return;}
        if(pos==0){state->header_scope_key.kind=1;state->header_scope_key.pad=0;}
        state->header_scope_key.name[pos]=lower_ascii(c);state->header_name_len=pos+1;state->header_scope_key.name_len=pos+1;state->header_scope_key.prefix_len=(4+pos+1)*8;return;
    }
    if(state->scope_active)inspect_scoped_byte(ctx,state->active_scope_id,c);
    if(state->header_kind==2){static const char media[]="application/x-www-form-urlencoded";__u32 pos=state->content_type_index;if(pos==0&&(c==' '||c=='\t')){}else if(pos<33){if(lower_ascii(c)==media[pos])state->content_type_index=pos+1;else state->content_type_valid=0;}else if(pos==33){if(c==';')state->content_type_index=35;else if(c==' '||c=='\t')state->content_type_index=34;else state->content_type_valid=0;}else if(pos==34){if(c==';')state->content_type_index=35;else if(c!=' '&&c!='\t')state->content_type_valid=0;}}
    if(state->header_kind==1){if(c==' '||c=='\t'){if(state->content_length_digits>0)state->content_length_trailing_space=1;return;}if(c<'0'||c>'9'||state->content_length_trailing_space){parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}__u32 digit=c-'0';if(state->body_remaining>(0xffffffffU-digit)/10){parser_error(ctx,REQUEST_FLAG_OVERSIZE);return;}state->body_remaining=state->body_remaining*10+digit;if(state->body_remaining>MAX_REQUEST_SIZE)state->request_flags|=REQUEST_FLAG_OVERSIZE;state->content_length_digits++;}
}

static __always_inline void parse_http_line_byte(struct parser_ctx *ctx, char c)
{
    struct conn_state *state=ctx->state;
    if(state->saw_cr){state->saw_cr=0;if(c!='\n'){parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}int rc=finish_line(ctx);if(rc==-2)parser_error(ctx,REQUEST_FLAG_UNSUPPORTED);else if(rc==-3)parser_error(ctx,REQUEST_FLAG_OVERSIZE);else if(rc!=0)parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}
    if(c=='\r'){state->saw_cr=1;return;}if(c=='\n'){parser_error(ctx,REQUEST_FLAG_MALFORMED);return;}
    if(state->line_len<0xffffffffU)state->line_len++;
    if(state->parser_mode==PARSER_REQUEST_LINE)parse_request_line_byte(ctx,c);else parse_header_byte(ctx,c);
}

static __always_inline long parse_one_byte_inner(__u32 i, void *opaque)
{
    struct parser_ctx *ctx=opaque;struct conn_state *state=ctx->state;
    i&=(MAX_DATA_SIZE-1);char c=ctx->scratch->data[i];
    if(state->parser_mode==PARSER_REQUEST_LINE&&!state->request_started&&((c>='A'&&c<='Z')||(c>='a'&&c<='z'))){state->request_sequence++;state->active_request_sequence=state->request_sequence;state->request_started=1;state->correlation_known=0;update_request_verdict(ctx,VERDICT_PENDING,CORRELATION_UNKNOWN,INSPECTION_INCOMPLETE,TRACKING_INCOMPLETE);}
    inspect_request_byte(ctx,c);
    if(state->parser_mode==PARSER_DISABLED)return 0;
    if(state->request_length<0xffffffffU)state->request_length++;if(state->request_length>MAX_REQUEST_SIZE)state->request_flags|=REQUEST_FLAG_OVERSIZE;
    if(state->parser_mode==PARSER_BODY||state->parser_mode==PARSER_FORM_BODY){if(state->parser_mode==PARSER_FORM_BODY)inspect_form_body_byte(ctx,c);if(state->body_remaining>0)state->body_remaining--;if(state->body_remaining==0)complete_request(ctx);return 0;}
    parse_http_line_byte(ctx,c);return 0;
}

static __always_inline void emit_raw_chunk(struct parser_ctx *parser, __u64 seq,
                                             __u32 returned_len, __u32 offset,
                                             __u32 chunk_index, __u32 expected_chunks,
                                             __u32 data_len, __u32 flags)
{
    struct raw_chunk_event *event = bpf_ringbuf_reserve(&raw_events, sizeof(*event), 0);
    struct request_counters *counters = get_request_counters();
    if (!event) { if (counters) counters->raw_ringbuf_drops++; return; }
    struct ssl_read_context *read_ctx=get_ssl_read_context();
    if(!read_ctx){bpf_ringbuf_discard(event,0);return;}
    event->tgid = read_ctx->tgid;
    event->tid = (__u32)bpf_get_current_pid_tgid();
    event->ssl = read_ctx->ssl;
    event->read_sequence = seq;
    event->timestamp_ns = read_ctx->timestamp_ns;
    event->read_total_len = returned_len;
    event->read_offset = offset;
    event->chunk_index = chunk_index;
    event->expected_chunk_count = expected_chunks;
    event->data_len = data_len;
    event->flags = flags;
    event->event_type = 0;
    if (bpf_probe_read_kernel(event->data, data_len, parser->scratch->data) != 0) {
        if (counters) counters->raw_capture_failures++;
        bpf_ringbuf_discard(event, 0);
        return;
    }
    bpf_ringbuf_submit(event, 0);
    if (counters) { counters->raw_chunks_submitted++; counters->raw_bytes_submitted += data_len; }
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
    __u64 pid_tgid=bpf_get_current_pid_tgid();
    __u32 pid=pid_tgid>>32;
    struct ssl_args *args=bpf_map_lookup_elem(&active_args,&pid_tgid);
    if(!args) return 0;
    __s32 ret=(__s32)PT_REGS_RC(ctx);
    if(ret<=0){bpf_map_delete_elem(&active_args,&pid_tgid);return 0;}
    __u32 returned_len=(__u32)ret;
    __u32 safe_len=returned_len;
    __u32 capture_flags=0;
    if((__u64)returned_len>args->len){safe_len=args->len>0xffffffffULL?0xffffffffU:(__u32)args->len;capture_flags|=REQUEST_FLAG_CAPTURE_TRUNCATED;}
    if(safe_len>MAX_INSPECT_SIZE){safe_len=MAX_INSPECT_SIZE;capture_flags|=REQUEST_FLAG_CAPTURE_TRUNCATED;}
    if(capture_flags){struct request_counters *c=get_request_counters();if(c)c->raw_capture_truncated++;}
    __u32 zero=0;
    __u64 now=bpf_ktime_get_ns();
    struct conn_key key={.pid=pid,.pad=0,.ssl=args->ssl};
    struct conn_state *state=bpf_map_lookup_elem(&conn_states,&key);
    if(!state){struct conn_state *initial=bpf_map_lookup_elem(&conn_state_template,&zero);if(!initial){bpf_map_delete_elem(&active_args,&pid_tgid);return 0;}reset_request(initial);initial->last_seen_ns=now;bpf_map_update_elem(&conn_states,&key,initial,BPF_NOEXIST);state=bpf_map_lookup_elem(&conn_states,&key);}
    if(!state){bpf_map_delete_elem(&active_args,&pid_tgid);return 0;}
    struct ssl_read_context *read_ctx=bpf_map_lookup_elem(&ssl_read_contexts,&zero);
    if(!read_ctx){bpf_map_delete_elem(&active_args,&pid_tgid);return 0;}
    read_ctx->key.pid=pid;read_ctx->key.pad=0;read_ctx->key.ssl=args->ssl;read_ctx->tgid=pid;read_ctx->ret_len=ret;read_ctx->requested_len=args->len>0xffffffffULL?0xffffffffU:(__u32)args->len;read_ctx->safe_len=safe_len;read_ctx->capture_flags=capture_flags;read_ctx->chunk_index=0;read_ctx->expected_chunks=(safe_len+MAX_DATA_SIZE-1)/MAX_DATA_SIZE;read_ctx->byte_offset=0;read_ctx->timestamp_ns=now;read_ctx->ssl=args->ssl;
    struct parser_ctx parser={.state=state};
    if(now-state->last_seen_ns>CONN_STATE_TTL_NS){if(state->request_started){state->correlation_known=0;state->request_flags|=REQUEST_FLAG_TRACKING_LOST;emit_request(&parser,state->request_flags,0);}reset_request(state);}
    state->read_sequence++;
    read_ctx->read_sequence=state->read_sequence;
    bpf_tail_call(ctx,&parser_programs,0);
    parser_error(&parser,REQUEST_FLAG_CAPTURE_TRUNCATED);
    bpf_map_delete_elem(&active_args,&pid_tgid);
    return 0;
}

SEC("uprobe/ssl_parse_step")
int ssl_parse_step(struct pt_regs *ctx)
{
    __u64 pid_tgid=bpf_get_current_pid_tgid();
    __u32 pid=pid_tgid>>32;
    __u32 zero=0;
    struct ssl_args *args=bpf_map_lookup_elem(&active_args,&pid_tgid);
    struct ssl_read_context *read_ctx=bpf_map_lookup_elem(&ssl_read_contexts,&zero);
    if(!args||!read_ctx){bpf_map_delete_elem(&active_args,&pid_tgid);return 0;}
    struct conn_state *state=bpf_map_lookup_elem(&conn_states,&read_ctx->key);
    struct scan_buffer *scratch=bpf_map_lookup_elem(&scan_buffers,&zero);
    if(!state||!scratch){bpf_map_delete_elem(&active_args,&pid_tgid);return 0;}
    struct parser_ctx parser={.state=state,.scratch=scratch};
    if(read_ctx->chunk_index<read_ctx->expected_chunks){
        __u32 offset=read_ctx->chunk_index*MAX_DATA_SIZE;
        __u32 chunk_len=read_ctx->safe_len-offset;
        if(chunk_len>MAX_DATA_SIZE)chunk_len=MAX_DATA_SIZE;
        if(bpf_probe_read_user(scratch->data,chunk_len,(const void *)(args->buf+offset))!=0){read_ctx->capture_flags|=REQUEST_FLAG_CAPTURE_TRUNCATED;struct request_counters *c=get_request_counters();if(c)c->raw_capture_failures++;read_ctx->chunk_index=read_ctx->expected_chunks;}
        else {
            read_ctx->current_chunk_len=chunk_len;
            if(read_ctx->byte_offset==0)emit_raw_chunk(&parser,read_ctx->read_sequence,(__u32)read_ctx->ret_len,offset,read_ctx->chunk_index,read_ctx->expected_chunks,chunk_len,read_ctx->capture_flags);
            parser.callback_offset=read_ctx->byte_offset;
            __u32 batch=chunk_len-read_ctx->byte_offset;if(batch>MAX_PARSE_BATCH)batch=MAX_PARSE_BATCH;
            if(batch==0 || bpf_loop(batch,parse_one_byte,&parser,0)<0){read_ctx->capture_flags|=REQUEST_FLAG_CAPTURE_TRUNCATED;read_ctx->chunk_index=read_ctx->expected_chunks;}
            else {
                read_ctx->byte_offset+=batch;
                if(read_ctx->byte_offset<chunk_len){bpf_tail_call(ctx,&parser_programs,0);read_ctx->capture_flags|=REQUEST_FLAG_CAPTURE_TRUNCATED;read_ctx->chunk_index=read_ctx->expected_chunks;}
                read_ctx->chunk_index++;read_ctx->byte_offset=0;
            }
        }
    }
    if(read_ctx->chunk_index<read_ctx->expected_chunks){bpf_tail_call(ctx,&parser_programs,0);read_ctx->capture_flags|=REQUEST_FLAG_CAPTURE_TRUNCATED;}
    if(state->request_started&&state->is_malicious&&state->parser_mode!=PARSER_DISABLED)update_request_verdict(&parser,VERDICT_MALICIOUS,state->correlation_known?CORRELATION_RELIABLE:CORRELATION_UNKNOWN,INSPECTION_INCOMPLETE,TRACKING_INCOMPLETE);
    state->last_seen_ns=read_ctx->timestamp_ns;
    if(read_ctx->capture_flags)parser_error(&parser,read_ctx->capture_flags);
    bpf_map_delete_elem(&active_args,&pid_tgid);
    return 0;
}

SEC("uprobe/SSL_free")
int ssl_free_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    struct conn_key key = { .pid = pid, .pad = 0, .ssl = ssl };
    struct raw_chunk_event *event = bpf_ringbuf_reserve(&raw_events, sizeof(*event), 0);
    if (event) {
        event->tgid = pid; event->tid = (__u32)pid_tgid; event->ssl = ssl;
        event->timestamp_ns = bpf_ktime_get_ns(); event->event_type = 1;
        bpf_ringbuf_submit(event, 0);
    } else {
        struct request_counters *counters = get_request_counters();
        if (counters) counters->raw_ringbuf_drops++;
    }
    bpf_map_delete_elem(&conn_states, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
