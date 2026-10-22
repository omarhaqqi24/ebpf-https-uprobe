# Task: Increase eBPF Scan Capacity and Correlate Signature Detection with HTTP Requests

## Context

This project is `ebpf-https-uprobe`, implemented in Go with `cilium/ebpf`. It attaches uprobes/uretprobes to OpenSSL functions such as `SSL_read()` and `SSL_free()`.

The eBPF C program captures decrypted HTTPS plaintext in the `SSL_read()` return probe. It currently has:
- `MAX_DATA_SIZE = 1024`
- `TAIL_SIZE = 64`
- `MAX_SCAN_SIZE = MAX_DATA_SIZE + TAIL_SIZE`
- `MAX_SCAN_BYTES = 1024`
- `MAX_REQUEST_SIZE = 8192`

The program has a streaming HTTP/1.1 request parser and a separate signature-scanning path. Request events are emitted through `request_events`, while signature detections currently use a separate event path. Signature detection is not yet correlated with individual requests.

## Goals

1. Increase the plaintext processing capacity from 1024 to 4096 bytes per `SSL_read()` invocation, while preserving correct buffer bounds and eBPF verifier compatibility.
2. Correlate signature matches with the HTTP request currently being parsed.
3. Emit request-level detection results so an individual request can be marked malicious.
4. Preserve the existing Go loader and dataset-writing workflow where practical.

## Phase 1: Audit and increase buffer capacity

Before editing, inspect the complete source and identify every use of:
- `MAX_DATA_SIZE`
- `TAIL_SIZE`
- `MAX_SCAN_SIZE`
- `MAX_SCAN_BYTES`
- `MAX_REQUEST_SIZE`
- Scratch buffer declarations and map value sizes
- Scan loops, tail-copy logic, and all indexes derived from read lengths

Then:
1. Set the initial target to `MAX_DATA_SIZE = 4096`.
2. Ensure all buffers can safely hold the required data. The combined scan range must account for both the retained tail and the new plaintext bytes.
3. Fix the current scan-range limitation where the combined range can be larger than `MAX_SCAN_BYTES`, potentially leaving trailing bytes unscanned.
4. Keep per-read capacity separate from maximum HTTP request size.
5. Do not blindly increase all constants. Choose limits based on actual buffer sizes, verifier constraints, memory usage, and scan-loop complexity.
6. Do not allocate large temporary arrays on the BPF stack. Prefer appropriately sized map-backed/per-CPU scratch buffers where suitable.
7. Preserve the existing tail-overlap behavior and verify that cross-chunk signatures remain detectable.

## Phase 2: Correlate signature scanning with request parsing

Inspect the current parser and signature matcher before choosing the implementation.

The preferred design is streaming inspection with per-request state:
1. Initialize request-specific detection state when a new HTTP request begins.
2. Inspect plaintext bytes in the context of the request currently being parsed.
3. Preserve enough signature-matching state across `SSL_read()` chunks to detect patterns split between reads.
4. Never allow a match to span across two different HTTP requests.
5. If a signature matches, record a malicious flag and the matched rule identifier or bitmask in the current request state.
6. When the request completes, emit a request event containing the request identity and its verdict.
7. Reset request-specific signature state before parsing the next request, including when multiple requests occur in one `SSL_read()` result.
8. Keep connection-level telemetry separate from request-level verdicts. Do not copy a connection-level detection flag into every subsequent request.
9. Avoid implementing an expensive full-request scan in a single unbounded BPF loop. If the existing matching algorithm cannot safely support streaming state, explain the tradeoffs and propose a verifier-safe alternative before changing the architecture.

## Phase 3: Request event schema and Go integration

Extend the C `request_event` and corresponding Go structs consistently.

Include, where appropriate:
- `request_sequence`
- `request_length`
- `method`
- `uri`
- `http_version`
- `is_malicious` or an equivalent verdict field
- `matched_rules`
- Existing parser and capture diagnostic flags

Update Go decoding, validation, logging, and `dataset.jsonl` output to include the new fields.

Maintain exact struct layout compatibility between C and Go. Check alignment and padding for fields such as `__u64`, pointers, and integer flags. Do not assume Go struct layout matches C automatically.

Define request identity and sequence semantics explicitly. Ring-buffer emission failure must not silently cause an ambiguous request identity or turn a potentially malicious request into benign.

Keep the existing standalone signature event if it remains useful for connection-level telemetry, but do not use it as the source of the request verdict unless it can be reliably correlated.

## Phase 4: Conservative error handling

Preserve and test explicit handling for:
- Oversized requests
- Truncated capture
- Malformed HTTP request lines or headers
- Unsupported `Transfer-Encoding`/chunked framing
- Duplicate or invalid `Content-Length`
- Ring-buffer reservation/output failure
- Parser state expiration and SSL object cleanup

Do not classify incomplete, unsupported, or malformed traffic as benign by default. Keep parser/capture status separate from the malicious verdict.

Audit the existing TTL reset logic to ensure parser state and signature state cannot become inconsistent.

## Phase 5: Tests and validation

Create or update tests covering:
1. A normal GET request.
2. A request containing a known test signature.
3. Two requests in one `SSL_read()` result, with only one malicious.
4. One request split across multiple `SSL_read()` results.
5. A signature split across two reads.
6. A signature at the end of the scan range.
7. A malicious request followed by a benign request on the same SSL connection.
8. Payloads near 4096 bytes.
9. Requests near the 8192-byte request limit.
10. Unsupported framing, malformed input, and capture truncation.
11. Ring-buffer output failure and parser-state recovery.

Verify:
- The BPF program compiles and passes the kernel verifier.
- The Go program compiles.
- C and Go event layouts match.
- Each completed request has an independently computed verdict.
- Detection state does not leak between requests.
- No bytes are read outside the captured plaintext or buffer bounds.

## Constraints

- Keep HTTP parsing and signature-to-request correlation in kernel space for this iteration.
- Keep Go responsible for event consumption, logging, and dataset output.
- Do not claim that detecting a malicious request automatically blocks it. This task is for request-level detection and verdict reporting, not yet enforcement.
- Avoid unrelated refactoring.
- Do not silently remove existing signature rules or change their semantics.

## Deliverables

1. A concise summary of the original bugs and design decisions.
2. The modified source files.
3. A list of changed constants and buffer sizes with explanations.
4. Build and verifier results.
5. Test cases and actual results.
6. Known limitations, especially HTTP framing, oversized requests, and event-loss behavior.

Inspect the current implementation first, then implement the smallest coherent change set. Do not report tests as passing unless they were actually run.
