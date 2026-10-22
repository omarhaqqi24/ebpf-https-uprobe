# Nginx eBPF verdict module

This is a standalone dynamic HTTP module for the installed Ubuntu Nginx 1.24.0
ABI. It reads and consumes metadata-only verdicts from the pinned
`request_verdicts` BPF hash map. It never reads request body bytes.

## Correlation model

The module constructs the same key as eBPF:

`(getpid(), r->connection->ssl->connection, r->connection->requests)`

The 1.24 headers expose the TLS `SSL*` as
`ngx_connection_t.ssl->connection`. Nginx increments the client connection's
`requests` counter in `ngx_http_create_request()` for each main HTTP request;
internal redirects and subrequests do not allocate another main request. The
eBPF side assigns its sequence at the first method byte. This is intended to
align for valid HTTP/1.1 requests on the same worker and SSL object. It must be
kept under regression testing; a missing, expired, incomplete, unsupported, or
uncorrelated verdict follows the configured fallback.

The module only correlates TLS HTTP/1.1 requests that are not chunked. Nginx
currently has the HTTP/2 module compiled in but the OJS vhosts do not enable
HTTP/2. If enabled later, HTTP/2 requests will take the configured fallback
because the eBPF parser does not decode HTTP/2 frames. Chunked requests also
take fallback; the eBPF tracker does not parse chunked framing.

The access-phase handler reads and buffers the body with Nginx's
`ngx_http_read_client_request_body()` API, then looks up the verdict. This lets
the uretprobe synchronously update the map before Nginx's body callback runs.
For allowed requests, the buffered body remains available to the normal
upstream handler. No busy-wait is used. A main request is checked once; internal
subrequests do not perform a second verdict lookup.

## Build

Build against the exact Nginx source version and base configure flags used by
the installed package. Do not replace the system Nginx binary. On Ubuntu, the
`nginx-dev` package provides `/usr/share/nginx/src/conf_flags` for this build.

```sh
sudo apt install nginx-dev dpkg-dev build-essential libssl-dev libpcre2-dev zlib1g-dev
apt source nginx
cd nginx-1.24.0
source /usr/share/nginx/src/conf_flags
./configure "${NGX_CONF_FLAGS[@]}" \
  --add-dynamic-module=/home/waf/ebpf-https-uprobe/nginx
make modules
```

Use Bash for the `conf_flags` array. The resulting object is
`objs/ngx_http_ebpf_waf_module.so`. Copy it to a versioned module directory and
test a separate configuration with the installed `nginx -t -p <test-prefix> -c
<test-config>` before adding `load_module` to the live configuration. Do not
reload the service until the isolated tests pass and the configuration has
been reviewed.

## Configuration

Load the module at top level and configure one shared map path inside `http`:

```nginx
load_module /usr/lib/nginx/modules/ngx_http_ebpf_waf_module.so;

http {
    ebpf_waf_verdict_map /sys/fs/bpf/ebpf-https-uprobe/request_verdicts;

    server {
        listen 3501 ssl;
        # Existing TLS and OJS directives...
        ebpf_waf_mode observe;
        ebpf_waf_on_verdict_unavailable allow;
        ebpf_waf_block_signatures TRAVERSAL_RAW TRAVERSAL_XML_ENTITY;
    }
}
```

The default mode is `observe`; it logs the decision and always allows the
request. `reject` returns HTTP 403 only for a reliable, complete malicious
verdict whose first signature is in the configured blocking set. The initial
set is traversal raw and XML entity. `FILE_NAME_TAG` is intentionally not a
blocking signature.

`ebpf_waf_on_verdict_unavailable` accepts `allow` or `deny`. In `observe` mode
the request always continues. In `reject` mode `allow` avoids outages but lets
through requests whose verdict cannot be established; `deny` fails closed and
can reject benign traffic during detector/map outages or when framing is
unsupported. The module defaults to `allow`.

## Map startup and permissions

The detector accepts `-verdict-map` and `-nginx-group` flags (or
`EBPF_WAF_VERDICT_MAP` and `EBPF_WAF_NGINX_GROUP` before privilege escalation).
By default it pins at
`/sys/fs/bpf/ebpf-https-uprobe/request_verdicts`, sets the map file to
`root:www-data` mode `0660`, and makes the dedicated parent directory
traversable by that group. The detector owns map creation and expiration
cleanup; Nginx opens the map once per worker and consumes entries once. The
detector must start before Nginx workers if reject mode is to have a map. If
Nginx starts first, its configured fallback applies until workers restart and
open the map. The bpffs mount root itself must also allow the worker to
traverse `/sys/fs/bpf`; on this host it was `root:root 0700`, so traversal had
to be enabled before the worker could open the dedicated map directory. Keep
the dedicated map directory and map file restricted to the Nginx worker group.

The map key is 24 bytes: `u32 tgid`, `u32 pad`, `u64 ssl`, `u64 sequence`. The
value is 40 bytes: `u32 status`, `u32 first_signature`, `u64 updated_ns`,
`u64 expires_ns`, then four `u32` fields for correlation, inspection, tracking,
and diagnostic flags. Entries expire after five minutes and are also deleted
on Nginx lookup. `SSL_free()` intentionally does not delete completed entries.
Failed map updates are counted and never converted into a clean verdict.

Only `clean` after complete inspection/framing and `malicious` after a complete
request can be enforced. `pending`, `incomplete`, missing, stale, and
uncorrelated entries use the fallback policy. The Nginx module logs map misses,
fallbacks, observe decisions, allows, and HTTP 403 rejections without logging
request bodies.

## Validation performed

The module was built against the Ubuntu Nginx 1.24.0 package's base configure
flags and loaded by the installed `/usr/sbin/nginx` binary using a temporary
configuration on a loopback test port, with a harmless local HTTP upstream.
The test used the actual detector and pinned-map ABI and did not change or
reload the system service configuration. Results:

- In reject mode, benign POST returned 204 and reached the test upstream.
- `poc-2.xml` returned 403 and did not reach the test upstream; the detector
  reported `TRAVERSAL_XML_ENTITY`.
- On one TLS keep-alive connection, requests 1 and 2 were allowed, malicious
  request 3 was rejected, and benign request 4 was allowed. Nginx and eBPF
  logged matching TGID, SSL pointer, and request sequences 1 through 4.
- In observe mode, the PoC returned 204, reached upstream, and logged
  `would_reject=1`.
- A small XML body containing only `<file_name>` was allowed.
- With a missing map and `deny` fallback, a benign GET returned 403 and did not
  reach upstream. Chunked framing with `allow` fallback returned 204 and
  reached upstream with an `unsupported_chunked_framing` diagnostic.
- A 2 KiB prefix before the XML PoC still produced a reliable malicious
  verdict and 403 after the detector scanned 4096 bytes.

These tests establish the module's behavior against the isolated Nginx build
and test upstream. They do not establish correctness across all OJS traffic.
Keep HTTP/2 disabled and
use an explicit fallback for chunked, parser-error, capture-truncated, and
other uncorrelated traffic. The system Nginx configuration has not been
modified or reloaded; review the example configuration and repeat the isolated
checks with the intended production worker group before enabling it for OJS.
