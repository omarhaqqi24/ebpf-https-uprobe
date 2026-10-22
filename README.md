# eBPF HTTPS WAF pre-filter

The `SSL_read()` uretprobe copies decrypted plaintext into a per-CPU 4096-byte
scratch buffer and feeds it to both a streaming signature scanner and a minimal
HTTP/1.1 request tracker. Request bodies are never sent to userspace or written
to `dataset.jsonl`.

## Detection and request identity

The scanner maintains a 24-byte rolling window across chunks and reads. The
first configured signature in a reliably tracked request immediately marks the
request malicious, records that signature, and emits a metadata-only detection
event. It then skips further signature comparisons for that request while the
tracker continues through the framing boundary. A single signature is
sufficient; composite rule bits are not used as a verdict.

Request sequences are assigned at the first method byte. Completed request
events carry `(TGID, SSL pointer, sequence)`, request metadata, verdict, and
inspection/tracking statuses. Immediate detection events are terminal logs and
do not become extra dataset rows. Only completed request events are appended to
`dataset.jsonl`; metadata truncation and oversize threshold flags remain
visible in those rows.

## Framing and limits

The tracker handles HTTP/1.1 request lines, header termination, and a single
valid `Content-Length`. It does not implement chunked transfer encoding. On
malformed or unsupported framing it marks correlation unknown and disables
tracking for that SSL object; the scanner keeps inspecting subsequent plaintext
and reports the first match in each `SSL_read()` result as unattributed. It
restarts matching on the next result so later traffic remains scannable. It does
not guess request boundaries or invent a sequence after tracking is lost.

Long header values and request metadata do not disable scanning. Method and URI
metadata are bounded to their event fields and explicitly flagged when
truncated. Requests above the 8192-byte reporting threshold continue to be
tracked and scanned without retaining their body.

Each positive `SSL_read()` result is processed in up to four bounded 4096-byte
chunks (16 KiB total per call). The code never reads past either the returned
plaintext length or the destination-buffer capacity supplied to `SSL_read()`.
If a result exceeds that per-call work limit, or a safe user-memory read fails,
the available prefix is scanned and a capture-incomplete diagnostic is emitted;
the unprocessed suffix is not claimed as inspected. Scanner matches can span
chunk boundaries.

Ring-buffer event loss is counted separately for request and detection events.
`SSL_free()` removes per-connection state. This detector only logs and records
matches in kernel space. The optional Nginx module described below consumes
per-request verdicts and applies HTTP-level rejection; the detector does not
drop encrypted packets.

## Request-level enforcement prototype

The detector writes verdicts synchronously to a pinned BPF hash map keyed by
`(TGID, SSL pointer, request sequence)`. The standalone module in `nginx/`
reads and consumes those metadata-only verdicts in the Nginx access phase after
the request body has been buffered. `observe` is the default; `reject` returns
HTTP 403 only for reliable, complete `TRAVERSAL_RAW` or
`TRAVERSAL_XML_ENTITY` verdicts selected by policy. `FILE_NAME_TAG` is not a
blocking signature.

This prototype correlates TLS HTTP/1.1 requests using Nginx's per-connection
request count and the same `SSL*` exposed by its public headers. Chunked
requests, HTTP/2, and incomplete or uncertain tracking follow the configured
fallback. Keep HTTP/2 disabled on protected routes until the eBPF parser
supports it. See [`nginx/README.md`](nginx/README.md) for build, permissions,
configuration, and validation details. The live OJS Nginx configuration has
not been changed or reloaded.
