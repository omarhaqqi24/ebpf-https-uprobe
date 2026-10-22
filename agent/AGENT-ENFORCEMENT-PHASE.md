# Task: Implement Request-Level Enforcement for the eBPF HTTPS WAF

## 1. Project Context

Repository: `ebpf-https-uprobe`

The project currently uses:
- Go and `github.com/cilium/ebpf`
- eBPF C programs attached to OpenSSL `SSL_read()` entry/return probes
- An `SSL_free()` uprobe to clean up connection state
- Kernel-space signature inspection over decrypted HTTPS plaintext
- HTTP/1.1 request tracking in eBPF
- Per-request sequence numbers and verdicts
- Ring buffers for detection events and completed request events
- Go for event processing, logging, and `dataset.jsonl`

Current tests sent seven XML PoC requests to the local OJS test environment. The detector reported all seven as malicious:
- 2 detections with `TRAVERSAL_RAW`
- 5 detections with `TRAVERSAL_XML_ENTITY`

Each reported request had reliable correlation and completed tracking. This is evidence for the tested samples only, not proof of general detection accuracy.

## 2. Objective

Extend the existing detection-only prototype into a request-level enforcement prototype.

The intended behavior is:

1. eBPF inspects decrypted plaintext.
2. When a configured blocking signature matches, eBPF records a malicious verdict in a shared BPF map.
3. An Nginx HTTP module retrieves the verdict for the exact request.
4. Nginx rejects the malicious request with HTTP 403 before forwarding it to PHP-FPM/OJS.
5. Benign requests continue normally.
6. Go continues to consume detection and request events for logging and dataset generation.

The enforcement decision must not depend on a Go goroutine receiving a ring-buffer event quickly enough.

Do not implement packet dropping through XDP/TC as the primary solution. The objective is to reject an HTTP request after TLS decryption while preserving unrelated requests on the same keep-alive connection.

## 3. Phase 1: Audit the actual runtime environment

Inspect the current source tree and deployment before implementing enforcement.

Determine:

- The actual Nginx binary, version, build options, and worker model.
- Which process terminates TLS.
- Which `libssl.so` is loaded by the Nginx workers.
- Whether the existing `SSL_read()` probes observe the same SSL objects used by Nginx.
- Whether the current eBPF request parser and Nginx request parser both handle the target traffic as HTTP/1.1.
- Whether HTTP/2, chunked transfer encoding, or other unsupported framing can enter the protected route.
- How the current request sequence is allocated, when it resets, and how it can become desynchronized.
- Whether the installed Nginx supports the required HTTP module development and build workflow.

Use the installed Nginx headers and development guide for the target version. Avoid copying undocumented internal functions or relying on private interfaces unnecessarily.

Do not replace the system Nginx binary, alter unrelated virtual hosts, or restart production services as part of an automatic build step. Build the proposed module and provide explicit integration instructions.

If the required Nginx-to-eBPF request correlation cannot be made reliable with the current architecture, report the exact blocker and implement only the safe observe-mode integration until the issue is resolved.

## 4. Phase 2: Define the enforcement policy

Implement configurable modes:

### `observe`
- Default mode.
- Continue normal request processing.
- Log whether a blocking policy would have rejected a request.
- Do not interfere with existing OJS functionality.

### `reject`
- Reject requests whose verdict matches an explicitly configured blocking policy.
- Require reliable request correlation.
- Return HTTP 403 before the request is forwarded to PHP-FPM/OJS.

### Handling incomplete or unavailable verdicts

Add a configuration option for the behavior when:
- The verdict map cannot be opened or read.
- No matching verdict exists.
- The verdict has expired.
- Request correlation is unknown.
- Inspection or framing is incomplete.

Make the fallback policy explicit, such as `allow` or `deny`, rather than silently treating unknown state as benign. Keep `observe` as the default.

Document the operational risks of each fallback choice.

### Blocking signatures

Do not automatically block every current detection signature.

For the initial lab policy, allow configuration of the signatures that can trigger rejection. Start with:
- `TRAVERSAL_RAW`
- `TRAVERSAL_XML_ENTITY`

Do not reinstate `FILE_NAME_TAG` as a blocking signature without additional evidence, because it can also occur in legitimate XML.

Keep detection telemetry separate from the blocking decision. A detection signature may be logged without being configured to cause rejection.

## 5. Phase 3: Create a shared verdict map

Add a BPF map intended specifically for enforcement verdicts. Reuse existing verdict fields where practical, but do not rely solely on the transient request parser state.

Use a request key based on:
- Process ID (`TGID`)
- SSL pointer
- Stable request sequence

Conceptual C schema:

```c
struct verdict_key {
    __u32 tgid;
    __u32 pad;
    __u64 ssl;
    __u64 request_sequence;
};

enum verdict_status {
    VERDICT_PENDING = 0,
    VERDICT_CLEAN = 1,
    VERDICT_MALICIOUS = 2,
    VERDICT_INCOMPLETE = 3,
};
```

This is a design reference, not a requirement to copy the declarations verbatim. Follow the repository's existing naming conventions and ABI constraints.

The value should contain:
- Verdict status
- First matching signature or approved blocking-rule identifier
- Timestamp
- Expiration or validity metadata
- Correlation status
- Inspection/tracking status
- Optional policy identifier

Requirements:

1. A stable request identity must be assigned when the HTTP request begins to be tracked.
2. A malicious verdict must be written synchronously before the detection event is emitted.
3. A clean verdict must be written only after inspection and request framing have completed successfully, with no matching signature.
4. Incomplete inspection must not be represented as clean.
5. The verdict must survive parser reset and request completion until the enforcement module consumes it or it expires.
6. Prevent stale verdicts from matching a reused SSL pointer, process, or request sequence.
7. Handle map update failures and map capacity exhaustion explicitly.
8. Preserve per-SSL cleanup without deleting a completed verdict before Nginx has consumed it.
9. Design entry expiry, stale-entry cleanup, and one-time consumption.
10. Do not store plaintext request bodies in the verdict map.

Use the existing cilium/ebpf APIs and library versions in the repository. Do not invent unavailable APIs.

## 6. Phase 4: Share the verdict map safely

Pin the required map to a configurable bpffs path, for example:

`/sys/fs/bpf/ebpf-https-uprobe/request_verdicts`

The path must be configurable rather than hard-coded throughout the source.

Implement:
- Map pinning and startup validation in Go.
- Correct access permissions for the Nginx worker process.
- A compatible method for the Nginx module to open and read the pinned map.
- Cleanup and lifecycle rules that do not remove the map while the enforcement module is using it.

Inspect the existing `cilium/ebpf` version before implementing the pinning workflow.

The Nginx module may use compatible libbpf userspace APIs or another suitable BPF map access method supported by the installed environment.

Document the startup order and map ownership. If Nginx starts before the detector creates the pinned map, handle the case according to the configured observe/reject fallback policy.

The Nginx module should open the map at a suitable worker lifecycle point, manage file descriptors safely, and avoid opening the map repeatedly on every request.

## 7. Phase 5: Implement the Nginx HTTP enforcement module

Create a standalone module in a dedicated directory, for example:

`nginx/ngx_http_ebpf_waf_module.c`

Include the appropriate module build configuration file and instructions for the installed Nginx version.

The module should expose configuration directives similar to:

```nginx
ebpf_waf_mode observe;
ebpf_waf_verdict_map /sys/fs/bpf/ebpf-https-uprobe/request_verdicts;
ebpf_waf_on_verdict_unavailable allow;
```

These are illustrative directive names. Adapt them to the implementation.

### Request handling

The module must:

1. Run before the request is forwarded to the upstream application.
2. Identify the current main HTTP request and its TLS connection.
3. Obtain the corresponding SSL pointer through an API available in the installed Nginx headers, if supported.
4. Maintain a per-connection request sequence or another proven correlation mechanism.
5. Query the verdict map using the exact request identity.
6. Reject a confirmed malicious request with HTTP 403 in `reject` mode.
7. Allow confirmed clean requests to continue normally.
8. Preserve detection logging for requests that are not configured to be blocked.
9. Handle missing, incomplete, expired, and uncorrelated verdicts according to the explicit fallback policy.

### Request body handling

The detection signature may occur in the body, so do not make the enforcement decision solely from request headers.

Use Nginx's supported request-body reading API and its asynchronous callback model. Ensure the verdict lookup happens when the detector has had an opportunity to process the body bytes read by Nginx.

Requirements:
- Do not busy-wait or block an Nginx worker waiting for a verdict.
- Handle synchronous callback invocation and asynchronous completion correctly.
- Do not finalize or resume the same request twice.
- Respect Nginx request-body buffering, temporary files, client body size limits, and error handling.
- Ensure the buffered request body can still be consumed correctly by the upstream handler when the request is allowed.
- Reject a malicious request before it reaches PHP-FPM/OJS.

Follow the installed version's module-development documentation for access-phase return codes, body-read callbacks, and request finalization.

## 8. Phase 6: Solve request-sequence correlation explicitly

This is a critical correctness requirement.

The eBPF parser assigns `request_sequence` while processing decrypted HTTP/1.1 bytes. Nginx has its own request lifecycle. Do not assume their counters remain synchronized without validation.

Design a per-connection correlation mechanism that addresses:
- HTTP keep-alive
- Multiple requests in sequence
- Request pipelining where supported
- Internal redirects and Nginx subrequests
- Parser errors
- Unsupported HTTP framing
- Capture truncation
- SSL object reuse
- Concurrent Nginx workers
- Requests that complete without a matching detection event

A detection for request N must never reject request N+1.

If the existing key `(TGID, SSL pointer, request_sequence)` cannot be reliably reconstructed by Nginx, propose a better correlation method based on the available Nginx APIs and eBPF attachment points.

Never use only client IP, URI, “latest detection on the connection”, or a timestamp guess to associate a verdict with a request.

If correlation is unknown, do not report successful request-level enforcement. Emit a diagnostic and follow the configured fallback policy.

For traffic not correctly supported by the current eBPF HTTP/1.1 parser, ensure the enforcement module does not misassociate its verdicts with later requests.

## 9. Phase 7: Keep the Go detector and dataset workflow compatible

Update `main.go` only as needed.

Preserve:
- Signature detection logs
- Request tracking diagnostics
- `dataset.jsonl`
- Existing request metadata
- Per-request malicious verdicts
- Counters for lost events, failed map updates, and unattributed detections where applicable

Go should not be the synchronous authorization point for the Nginx request.

Add structured logs or counters for:
- Enforcement mode
- BPF verdict updates and failures
- Map expiry or missing entries
- Nginx verdict lookups
- Correlation mismatches
- Requests rejected with HTTP 403
- Requests allowed
- Fallback decisions

Do not log plaintext request bodies.

Make sure a successful verdict-map update remains useful even if the diagnostic ring buffer is full.

## 10. Phase 8: Tests and proof of enforcement

Use only the authorized local OJS test environment.

Run the current detector regression suite before changing the enforcement path. Preserve the seven confirmed detections as regression tests.

Test at minimum:

### Detector and verdict map
1. A request with `TRAVERSAL_RAW`.
2. A request with `TRAVERSAL_XML_ENTITY`.
3. A request with no blocking signature.
4. A long request that crosses the 8192-byte reporting threshold.
5. A signature found in a later plaintext chunk.
6. Ring-buffer failure while the verdict map is still updated.
7. A failed map update.
8. An incomplete or unsupported request.

### Nginx enforcement
1. Observe mode logs the verdict but does not reject the request.
2. Reject mode returns HTTP 403 for a request with a configured blocking verdict.
3. Confirm that the rejected request never reaches PHP-FPM/OJS.
4. A benign request reaches the upstream application normally.
5. A benign XML document containing `<file_name>` is not blocked by that marker alone.
6. A malicious request followed by a benign request on the same keep-alive connection rejects only the malicious request.
7. Two sequential requests do not share each other's verdict.
8. Missing, stale, or uncorrelated verdicts follow the configured fallback policy.
9. Large request bodies work with Nginx memory and temporary-file buffering.
10. Unsupported framing does not silently lead to a false clean verdict or incorrect correlation.

For test verification:
- Check the client-observed HTTP status.
- Inspect Nginx access/error logs.
- Use a harmless upstream endpoint or application-side marker to establish whether the request reached the application.
- Confirm that benign requests remain functional.
- Do not infer rejection solely from a detector log or client-side error.

Keep false positives, false negatives, correlation failures, and enforcement failures as separate measurements.

## 11. Build and operational constraints

- Keep the existing detector functional in observe mode.
- Do not force a system-wide Nginx replacement.
- Do not silently edit unrelated Nginx configuration.
- Provide exact build and installation commands for the installed environment.
- Run `nginx -t` against a test configuration before recommending reload.
- Do not restart or reload the running service automatically.
- Do not claim enforcement works until an integration test confirms that malicious requests do not reach the upstream handler.

## 12. Deliverables

Provide:
1. An architecture review and actual correlation design.
2. The modified eBPF and Go source files.
3. Verdict-map schema and pinning workflow.
4. Nginx module source, build configuration, and build instructions.
5. Example Nginx configuration for observe and reject modes.
6. Build and eBPF verifier results.
7. Integration test results with actual HTTP status codes and upstream reachability results.
8. A summary of unsupported framing and fallback behavior.
9. Known limitations and recommended next steps.

Inspect the actual repository and runtime first. Then implement the smallest coherent end-to-end change. Do not claim a test passed unless it was actually executed.
