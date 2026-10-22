#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EBPF_WAF_SIG_TRAVERSAL_RAW   (1U << 5)
#define EBPF_WAF_SIG_TRAVERSAL_ENTITY (1U << 6)

enum {
    EBPF_WAF_OBSERVE = 0,
    EBPF_WAF_REJECT = 1
};

enum {
    EBPF_WAF_FALLBACK_ALLOW = 0,
    EBPF_WAF_FALLBACK_DENY = 1
};

enum {
    EBPF_WAF_VERDICT_PENDING = 0,
    EBPF_WAF_VERDICT_CLEAN = 1,
    EBPF_WAF_VERDICT_MALICIOUS = 2,
    EBPF_WAF_VERDICT_INCOMPLETE = 3
};

enum {
    EBPF_WAF_CORRELATION_RELIABLE = 0,
    EBPF_WAF_CORRELATION_UNKNOWN = 1
};

enum {
    EBPF_WAF_INSPECTION_COMPLETE = 0,
    EBPF_WAF_INSPECTION_STOPPED_AFTER_MATCH = 1,
    EBPF_WAF_INSPECTION_INCOMPLETE = 2
};

enum {
    EBPF_WAF_TRACKING_INCOMPLETE = 0,
    EBPF_WAF_TRACKING_COMPLETE = 1
};

typedef struct {
    ngx_str_t verdict_map;
} ngx_http_ebpf_waf_main_conf_t;

typedef struct {
    ngx_uint_t mode;
    ngx_uint_t fallback;
    ngx_uint_t blocking_signatures;
} ngx_http_ebpf_waf_loc_conf_t;

typedef struct {
    __u32 tgid;
    __u32 pad;
    __u64 ssl;
    __u64 request_sequence;
} ebpf_waf_verdict_key_t;

typedef struct {
    __u32 status;
    __u32 first_signature;
    __u64 updated_ns;
    __u64 expires_ns;
    __u32 correlation_status;
    __u32 inspection_status;
    __u32 tracking_status;
    __u32 flags;
} ebpf_waf_verdict_value_t;

typedef struct {
    ebpf_waf_verdict_key_t key;
    ngx_uint_t in_handler;
    ngx_uint_t completed;
    ngx_int_t result;
} ngx_http_ebpf_waf_ctx_t;

static ngx_int_t ngx_http_ebpf_waf_init(ngx_conf_t *cf);
static void *ngx_http_ebpf_waf_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_ebpf_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ebpf_waf_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_ebpf_waf_init_process(ngx_cycle_t *cycle);
static void ngx_http_ebpf_waf_exit_process(ngx_cycle_t *cycle);
static char *ngx_http_ebpf_waf_set_block_signatures(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ebpf_waf_handler(ngx_http_request_t *r);
static void ngx_http_ebpf_waf_body_ready(ngx_http_request_t *r);

static int ngx_http_ebpf_waf_verdict_fd = -1;

static ngx_conf_enum_t ngx_http_ebpf_waf_modes[] = {
    { ngx_string("observe"), EBPF_WAF_OBSERVE },
    { ngx_string("reject"), EBPF_WAF_REJECT },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t ngx_http_ebpf_waf_fallbacks[] = {
    { ngx_string("allow"), EBPF_WAF_FALLBACK_ALLOW },
    { ngx_string("deny"), EBPF_WAF_FALLBACK_DENY },
    { ngx_null_string, 0 }
};

static ngx_conf_bitmask_t ngx_http_ebpf_waf_signatures[] = {
    { ngx_string("TRAVERSAL_RAW"), EBPF_WAF_SIG_TRAVERSAL_RAW },
    { ngx_string("TRAVERSAL_XML_ENTITY"), EBPF_WAF_SIG_TRAVERSAL_ENTITY },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_ebpf_waf_commands[] = {
    { ngx_string("ebpf_waf_verdict_map"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET, offsetof(ngx_http_ebpf_waf_main_conf_t, verdict_map),
      NULL },

    { ngx_string("ebpf_waf_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ebpf_waf_loc_conf_t, mode),
      &ngx_http_ebpf_waf_modes },

    { ngx_string("ebpf_waf_on_verdict_unavailable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ebpf_waf_loc_conf_t, fallback),
      &ngx_http_ebpf_waf_fallbacks },

    { ngx_string("ebpf_waf_block_signatures"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_ebpf_waf_set_block_signatures,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ebpf_waf_loc_conf_t, blocking_signatures),
      &ngx_http_ebpf_waf_signatures },

      ngx_null_command
};

static ngx_http_module_t ngx_http_ebpf_waf_module_ctx = {
    NULL,
    ngx_http_ebpf_waf_init,
    ngx_http_ebpf_waf_create_main_conf,
    NULL,
    NULL,
    NULL,
    ngx_http_ebpf_waf_create_loc_conf,
    ngx_http_ebpf_waf_merge_loc_conf
};

ngx_module_t ngx_http_ebpf_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_ebpf_waf_module_ctx,
    ngx_http_ebpf_waf_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_ebpf_waf_init_process,
    NULL,
    NULL,
    ngx_http_ebpf_waf_exit_process,
    NULL,
    NGX_MODULE_V1_PADDING
};

static long
ngx_http_ebpf_waf_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    unsigned int size;

    switch (cmd) {
    case BPF_OBJ_GET:
        size = offsetof(union bpf_attr, file_flags)
               + sizeof(attr->file_flags);
        break;

    case BPF_MAP_LOOKUP_ELEM:
    case BPF_MAP_DELETE_ELEM:
        size = offsetof(union bpf_attr, flags) + sizeof(attr->flags);
        break;

    default:
        size = sizeof(*attr);
        break;
    }

    return syscall(__NR_bpf, cmd, attr, size);
}

static int
ngx_http_ebpf_waf_obj_get(const char *path)
{
    union bpf_attr attr;
    ngx_memzero(&attr, sizeof(attr));
    attr.pathname = (uintptr_t) path;
    return (int) ngx_http_ebpf_waf_bpf(BPF_OBJ_GET, &attr);
}

static ngx_int_t
ngx_http_ebpf_waf_lookup(const ebpf_waf_verdict_key_t *key,
    ebpf_waf_verdict_value_t *value)
{
    union bpf_attr attr;
    ngx_memzero(&attr, sizeof(attr));
    attr.map_fd = ngx_http_ebpf_waf_verdict_fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;
    if (ngx_http_ebpf_waf_bpf(BPF_MAP_LOOKUP_ELEM, &attr) != 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_ebpf_waf_delete(const ebpf_waf_verdict_key_t *key)
{
    union bpf_attr attr;
    ngx_memzero(&attr, sizeof(attr));
    attr.map_fd = ngx_http_ebpf_waf_verdict_fd;
    attr.key = (uintptr_t) key;
    if (ngx_http_ebpf_waf_bpf(BPF_MAP_DELETE_ELEM, &attr) != 0 && errno != ENOENT) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_uint_t
ngx_http_ebpf_waf_blocking_signature(ngx_uint_t mask, __u32 signature)
{
    return (signature & mask) != 0;
}

static ngx_uint_t
ngx_http_ebpf_waf_expired(const ebpf_waf_verdict_value_t *value)
{
    struct timespec ts;
    __u64 now;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 1;
    }
    now = (__u64) ts.tv_sec * 1000000000ULL + (__u64) ts.tv_nsec;
    return value->expires_ns <= now;
}

static ngx_int_t
ngx_http_ebpf_waf_unavailable(ngx_http_request_t *r,
    ngx_http_ebpf_waf_loc_conf_t *lcf, const char *reason)
{
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "ebpf_waf: mode=%s decision=fallback reason=%s pid=%P conn_requests=%ui",
        lcf->mode == EBPF_WAF_REJECT ? "reject" : "observe", reason,
        ngx_pid, r->connection->requests);

    if (lcf->mode == EBPF_WAF_REJECT && lcf->fallback == EBPF_WAF_FALLBACK_DENY) {
        r->keepalive = 0;
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_ebpf_waf_decide(ngx_http_request_t *r,
    ngx_http_ebpf_waf_loc_conf_t *lcf, ngx_http_ebpf_waf_ctx_t *ctx)
{
    ebpf_waf_verdict_value_t value;
    ngx_int_t rc;
    ngx_uint_t reject;
    const char *reason;

    if (ngx_http_ebpf_waf_verdict_fd < 0) {
        return ngx_http_ebpf_waf_unavailable(r, lcf, "map_unavailable");
    }

    ngx_memzero(&value, sizeof(value));
    rc = ngx_http_ebpf_waf_lookup(&ctx->key, &value);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, ngx_errno,
            "ebpf_waf: map_lookup=miss pid=%P ssl=%p seq=%ui",
            ngx_pid, (void *) (uintptr_t) ctx->key.ssl,
            (ngx_uint_t) ctx->key.request_sequence);
        return ngx_http_ebpf_waf_unavailable(r, lcf, "verdict_missing");
    }

    if (ngx_http_ebpf_waf_expired(&value)) {
        (void) ngx_http_ebpf_waf_delete(&ctx->key);
        return ngx_http_ebpf_waf_unavailable(r, lcf, "verdict_expired");
    }

    if (value.correlation_status != EBPF_WAF_CORRELATION_RELIABLE ||
        value.tracking_status != EBPF_WAF_TRACKING_COMPLETE ||
        (value.status != EBPF_WAF_VERDICT_CLEAN &&
         value.status != EBPF_WAF_VERDICT_MALICIOUS) ||
        (value.status == EBPF_WAF_VERDICT_CLEAN &&
         value.inspection_status != EBPF_WAF_INSPECTION_COMPLETE) ||
        (value.status == EBPF_WAF_VERDICT_MALICIOUS &&
         value.inspection_status != EBPF_WAF_INSPECTION_STOPPED_AFTER_MATCH))
    {
        (void) ngx_http_ebpf_waf_delete(&ctx->key);
        return ngx_http_ebpf_waf_unavailable(r, lcf, "verdict_incomplete_or_uncorrelated");
    }

    reject = value.status == EBPF_WAF_VERDICT_MALICIOUS &&
        ngx_http_ebpf_waf_blocking_signature(lcf->blocking_signatures,
                                             value.first_signature);
    (void) ngx_http_ebpf_waf_delete(&ctx->key);

    if (lcf->mode == EBPF_WAF_OBSERVE) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ebpf_waf: mode=observe decision=allow would_reject=%ui signature=%ui pid=%P ssl=%p seq=%ui",
            reject, (ngx_uint_t) value.first_signature, ngx_pid,
            (void *) (uintptr_t) ctx->key.ssl,
            (ngx_uint_t) ctx->key.request_sequence);
        return NGX_DECLINED;
    }

    if (reject) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "ebpf_waf: mode=reject decision=reject status=403 signature=%ui pid=%P ssl=%p seq=%ui",
            (ngx_uint_t) value.first_signature, ngx_pid,
            (void *) (uintptr_t) ctx->key.ssl,
            (ngx_uint_t) ctx->key.request_sequence);
        return NGX_HTTP_FORBIDDEN;
    }

    reason = value.status == EBPF_WAF_VERDICT_MALICIOUS
        ? "signature_not_in_block_policy" : "clean_verdict";
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "ebpf_waf: mode=reject decision=allow reason=%s signature=%ui pid=%P ssl=%p seq=%ui",
        reason, (ngx_uint_t) value.first_signature, ngx_pid,
        (void *) (uintptr_t) ctx->key.ssl,
        (ngx_uint_t) ctx->key.request_sequence);
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_ebpf_waf_handler(ngx_http_request_t *r)
{
    ngx_http_ebpf_waf_loc_conf_t *lcf;
    ngx_http_ebpf_waf_ctx_t *ctx;
    ngx_int_t rc;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ebpf_waf_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_ebpf_waf_module);
    if (ctx != NULL) {
        if (ctx->completed) {
            return ctx->result;
        }
        return NGX_DONE;
    }

    if (r->http_version != NGX_HTTP_VERSION_11) {
        return ngx_http_ebpf_waf_unavailable(r, lcf, "unsupported_http_version");
    }

#if (NGX_SSL)
    if (r->connection->ssl == NULL || r->connection->ssl->connection == NULL) {
        return ngx_http_ebpf_waf_unavailable(r, lcf, "tls_ssl_pointer_unavailable");
    }
#else
    return ngx_http_ebpf_waf_unavailable(r, lcf, "nginx_built_without_ssl");
#endif

    if (r->headers_in.chunked) {
        return ngx_http_ebpf_waf_unavailable(r, lcf, "unsupported_chunked_framing");
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return ngx_http_ebpf_waf_unavailable(r, lcf, "request_context_allocation_failed");
    }
    ctx->key.tgid = (uint32_t) getpid();
    ctx->key.ssl = (uintptr_t) r->connection->ssl->connection;
    ctx->key.request_sequence = r->connection->requests;
    ctx->in_handler = 1;
    ngx_http_set_ctx(r, ctx, ngx_http_ebpf_waf_module);

    rc = ngx_http_read_client_request_body(r, ngx_http_ebpf_waf_body_ready);
    ctx->in_handler = 0;
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ctx->completed = 1;
        ctx->result = rc;
        return rc;
    }

    if (ctx->completed) {
        ngx_http_finalize_request(r, NGX_DONE);
        return ctx->result;
    }

    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}

static void
ngx_http_ebpf_waf_body_ready(ngx_http_request_t *r)
{
    ngx_http_ebpf_waf_loc_conf_t *lcf;
    ngx_http_ebpf_waf_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ebpf_waf_module);
    if (ctx == NULL || ctx->completed) {
        return;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ebpf_waf_module);
    ctx->result = ngx_http_ebpf_waf_decide(r, lcf, ctx);
    ctx->completed = 1;

    if (!ctx->in_handler) {
        if (ctx->result == NGX_DECLINED) {
            r->write_event_handler = ngx_http_core_run_phases;
            ngx_http_core_run_phases(r);
        } else {
            ngx_http_finalize_request(r, ctx->result);
        }
    }
}

static void *
ngx_http_ebpf_waf_create_main_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_ebpf_waf_main_conf_t));
}

static void *
ngx_http_ebpf_waf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ebpf_waf_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }
    conf->mode = NGX_CONF_UNSET_UINT;
    conf->fallback = NGX_CONF_UNSET_UINT;
    conf->blocking_signatures = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *
ngx_http_ebpf_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ebpf_waf_loc_conf_t *prev = parent;
    ngx_http_ebpf_waf_loc_conf_t *conf = child;
    ngx_conf_merge_uint_value(conf->mode, prev->mode, EBPF_WAF_OBSERVE);
    ngx_conf_merge_uint_value(conf->fallback, prev->fallback, EBPF_WAF_FALLBACK_ALLOW);
    ngx_conf_merge_bitmask_value(conf->blocking_signatures,
        prev->blocking_signatures,
        EBPF_WAF_SIG_TRAVERSAL_RAW | EBPF_WAF_SIG_TRAVERSAL_ENTITY);
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ebpf_waf_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_ebpf_waf_handler;
    return NGX_OK;
}

static char *
ngx_http_ebpf_waf_set_block_signatures(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_ebpf_waf_loc_conf_t *lcf = conf;
    if (lcf->blocking_signatures == NGX_CONF_UNSET_UINT) {
        lcf->blocking_signatures = 0;
    }
    return ngx_conf_set_bitmask_slot(cf, cmd, conf);
}

static ngx_int_t
ngx_http_ebpf_waf_init_process(ngx_cycle_t *cycle)
{
    ngx_http_conf_ctx_t *http_ctx;
    ngx_http_ebpf_waf_main_conf_t *mcf;
    u_char *path;

    if (ngx_http_module.index == NGX_MODULE_UNSET_INDEX || cycle->conf_ctx == NULL) {
        return NGX_OK;
    }
    http_ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    if (http_ctx == NULL || http_ctx->main_conf == NULL) {
        return NGX_OK;
    }
    mcf = http_ctx->main_conf[ngx_http_ebpf_waf_module.ctx_index];
    if (mcf == NULL || mcf->verdict_map.len == 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
            "ebpf_waf: verdict map path is not configured");
        return NGX_OK;
    }

    path = ngx_pnalloc(cycle->pool, mcf->verdict_map.len + 1);
    if (path == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(path, mcf->verdict_map.data, mcf->verdict_map.len);
    path[mcf->verdict_map.len] = '\0';

    ngx_http_ebpf_waf_verdict_fd = ngx_http_ebpf_waf_obj_get((char *) path);
    if (ngx_http_ebpf_waf_verdict_fd < 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
            "ebpf_waf: cannot open verdict map \"%s\"; configured fallback will apply", path);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "ebpf_waf: opened shared verdict map \"%s\"", path);
    return NGX_OK;
}

static void
ngx_http_ebpf_waf_exit_process(ngx_cycle_t *cycle)
{
    if (ngx_http_ebpf_waf_verdict_fd >= 0) {
        (void) close(ngx_http_ebpf_waf_verdict_fd);
        ngx_http_ebpf_waf_verdict_fd = -1;
    }
}
