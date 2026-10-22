# Task: Decouple eBPF Signature Inspection from HTTP Parsing and Implement First-Match Request Detection

## 1. Project Context

Project: `ebpf-https-uprobe`

Technology:
- Go with `github.com/cilium/ebpf`
- eBPF C program attached to OpenSSL `SSL_read()` using uprobe/uretprobe
- `SSL_free()` uprobe for SSL connection-state cleanup
- Kernel-space inspection of decrypted HTTPS plaintext
- Go userspace consumes ring-buffer events, logs detections, and writes completed request records to `dataset.jsonl`

Primary source files:
- `bpf/ssl.bpf.c`
- `main.go`
- `rebuild.sh`
- Generated `bpf_bpfel.go`, `bpf_bpfeb.go`, and corresponding object files

The current implementation has a streaming HTTP/1.1 parser and signature detection that are too tightly coupled.

In `bpf/ssl.bpf.c`:
- `MAX_DATA_SIZE = 4096`
- `MAX_SCAN_SIZE = MAX_DATA_SIZE`
- `MAX_SCAN_BYTES = MAX_SCAN_SIZE`
- `MAX_REQUEST_SIZE = 8192`
- `MAX_HEADER_LINE = 256`
- `inspect_request_byte()` performs request-local signature matching.
- `parse_one_byte()` currently calls `inspect_request_byte()`.
- `parse_one_byte()` returns early when `parser_mode == PARSER_DISABLED`.
- `ssl_read_return()` caps `read_len` at `MAX_DATA_SIZE`. When the original `SSL_read()` return value exceeds the capped length, it currently reports a capture/parser error before processing the captured bytes through `bpf_loop()`.

The request event currently includes `request_sequence`, `signature_flags`, `matched_rules`, and `is_malicious`. However, `is_malicious` is derived from `request_matched_rules`, which requires certain combinations of signatures. This does not satisfy the new policy.

Inspect the actual working tree before making changes. The repository may have evolved since these notes were written.

## 2. Main Objectives

Implement the following design:

1. Signature inspection must operate independently of parser success or failure.
2. HTTP parsing should be reduced to the minimum necessary for identifying request boundaries and correlating detections with requests.
3. A single matching signature is sufficient to mark the current request as malicious.
4. After the first signature matches in a request, stop evaluating additional signatures for that request.
5. Continue minimal HTTP framing tracking after a match so that the program can identify where the request ends and reset detection state for the next request.
6. Do not stop signature inspection for later requests merely because an earlier request caused a parser error.
7. Handle plaintext results larger than 4096 bytes in bounded chunks without silently skipping the remaining captured bytes.
8. Preserve the existing signature definitions, Go loader, event handling, and dataset workflow wherever practical.

This task implements detection and request-level verdict reporting. It does not implement request blocking, Nginx enforcement, or automatic traffic rejection.

## 3. Required Architecture

Do not implement a sequential design that scans a buffer first and only parses it afterward if a signature is found. That approach can require buffering the entire request and can fail when the request spans multiple reads.

Instead, have two logically independent components consume the same decrypted plaintext stream:

### A. Signature scanner

Responsibilities:
- Inspect plaintext independently of whether the request tracker is healthy.
- Maintain the minimum rolling state required to detect a signature spanning two chunks.
- Maintain a per-request `inspection_done` flag.
- On the first matching signature:
  - Set the current request's malicious verdict.
  - Record the first matching signature.
  - Set `inspection_done = true`.
  - Emit a detection event promptly.
- Do not evaluate further signatures for that request after the first match.
- Reset signature matching state only when a new request boundary is reliably identified, or apply explicit degraded-tracking behavior if the boundary is unknown.

The scanner must not rely on `parser_mode != PARSER_DISABLED` as a prerequisite to inspect data.

### B. Minimal HTTP request tracker

Responsibilities:
- Identify the beginning of an HTTP/1.1 request.
- Keep a stable request identity and sequence number.
- Extract bounded metadata such as method, URI, and HTTP version when available.
- Detect the end of HTTP headers using the CRLF-CRLF delimiter.
- Inspect only the framing metadata necessary to establish the message boundary, particularly `Content-Length` and `Transfer-Encoding`.
- Track body progress without storing the complete body.
- Support multiple requests in one `SSL_read()` result.
- Support a single request spanning multiple `SSL_read()` results.
- Continue tracking request boundaries after a signature has matched, even though further signature matching is disabled for that request.

Do not parse and retain every HTTP header unnecessarily.

The tracker must not stop signature inspection if it encounters an oversized header, unsupported framing, malformed input, or another tracking error.

Keep the scanner's state independent from the tracker’s state.

## 4. Implement First-Match Detection

The detection policy must be:

`is_malicious = true` if and only if at least one configured signature matches the request.

The first matching signature is sufficient. Do not require combinations of multiple signatures or the existing composite rules before setting the malicious verdict.

Implement explicit request-local state, using suitable fields or equivalent existing structures:
- Stable request sequence/identity
- `is_malicious`
- `inspection_done`
- First signature identifier or bit
- Request framing/tracking status
- Bounded method and URI metadata
- Relevant diagnostic flags

These fields are conceptual. Reuse or adapt existing structures instead of duplicating state unnecessarily.

When a signature matches:
1. Save the signature that matched first.
2. Set the malicious verdict immediately in the persistent request state.
3. Mark inspection complete for this request.
4. Emit the detection event.
5. Skip future signature comparisons for this request.
6. Continue minimal request framing tracking.

When the current request completes, emit its final request event with the same request identity and verdict. Then reset the per-request signature state for the next request.

### Important rule semantics

The existing `evaluate_rules()` logic includes rules that require multiple signatures.

Do not use these composite rules as the gate for `is_malicious`. With the first-match policy, later signatures will deliberately not be evaluated for that request, so a composite rule may not be fully populated.

Preserve existing rule definitions where practical, but do not falsely report a composite rule as matched. Keep the first matching signature and the request verdict as the authoritative detection result.

Do not aggregate signature matches from multiple HTTP requests on the same SSL connection and use that aggregate to label an individual request malicious.

## 5. Decouple Scanner Execution from Parser Errors

Refactor the current `parse_one_byte()`/`inspect_request_byte()` coupling.

The byte-processing design must ensure that:
- Every successfully captured plaintext byte remains eligible for inspection while the scanner is active for its request.
- A parser state error cannot prevent the scanner from inspecting later bytes.
- `PARSER_DISABLED` or equivalent tracking failure applies to request identification only, not automatically to signature inspection.
- If the tracker cannot reliably identify a request boundary, the scanner continues in an explicit degraded mode.
- The program must not invent a request sequence or URI when correlation is unknown.

When request correlation is unavailable, report the result as an unattributed or incompletely correlated detection. Do not discard the match, and do not label the traffic benign simply because parsing failed.

If the tracker can safely recover synchronization, define the exact recovery conditions and test them. Do not resynchronize merely because arbitrary body bytes resemble an HTTP request line.

Avoid allowing a rolling signature window to span two different requests when reliable boundaries are known.

## 6. HTTP Framing and Parser Limits

Simplify the parser without sacrificing boundary correctness.

### Long headers and metadata limits

A header line longer than `MAX_HEADER_LINE` must not automatically disable signature inspection. Prefer tracking the line's delimiter and the small amount of metadata needed for framing, rather than storing the entire line.

If the method or URI is longer than the event metadata buffer, truncate the metadata explicitly and set a metadata-truncation flag. Do not abandon signature inspection only because the URI cannot fit in the output field.

Do not confuse metadata buffer capacity with the maximum size that can be inspected.

### Request size

`MAX_REQUEST_SIZE = 8192` must not act as a global cutoff for signature scanning.

A request larger than 8192 bytes must remain inspectable. The tracker can flag that the request exceeded a configured threshold while continuing to count or follow its framing without retaining the complete request in memory.

The scanner must continue inspecting each captured chunk until:
- A signature matches for the current request, or
- The request ends without a match, or
- A documented capture/work limit prevents complete inspection.

If a limit prevents complete inspection, report inspection as incomplete rather than benign.

### Content-Length and Transfer-Encoding

Support the existing known-good `Content-Length` framing behavior.

Do not silently interpret `Transfer-Encoding: chunked` as a bodyless request. If chunked framing is not implemented in this iteration, mark the request boundary as unsupported and preserve scanner operation. Detection must still be reported, with correlation status explicitly marked as unknown where appropriate.

Do not claim complete HTTP/1.1 framing support unless it has been implemented and tested.

## 7. Handle Large SSL_read Results Correctly

The current source caps `read_len` at `MAX_DATA_SIZE` and then treats an original return value exceeding that cap as a parser/capture error before running the normal byte-processing loop.

Fix this behavior.

Requirements:
1. Determine the valid readable length from the positive `SSL_read()` return value and recorded destination-buffer capacity.
2. Never read beyond the valid returned plaintext or destination-buffer bounds.
3. Process plaintext in bounded chunks suitable for verifier-safe eBPF execution and the scratch buffer size.
4. Preserve scanner rolling state and request tracking state between chunks.
5. Process all safely readable bytes rather than processing only the first 4096 bytes and silently losing the rest.
6. If the returned length exceeds the destination capacity or another genuine capture inconsistency occurs, scan the safe available bytes and emit an explicit capture diagnostic.
7. If processing every available byte is not feasible within safe eBPF execution limits, document and explicitly report the unprocessed range. Do not claim that the entire request was inspected.

Do not solve this by allocating an unbounded request buffer or a large temporary array on the BPF stack. Inspect map-backed/per-CPU scratch-buffer approaches and the verifier constraints before choosing the implementation.

Check all buffer indexes, offset arithmetic, loop limits, and pointer calculations.

## 8. Request Identity and Events

The request identity must remain stable from the time the tracker reliably identifies the current request until the final request event.

Define sequence semantics clearly. Prefer assigning the sequence when a request begins rather than assigning it only when completion is emitted. Avoid sequence ambiguity if ring-buffer submission fails.

Update the C event structures and matching Go structures together.

Request completion events should contain:
- Process ID
- SSL pointer
- Stable `request_sequence`
- Request length or an explicit length status
- Method, URI, and HTTP version when available
- `is_malicious`
- First matching signature or equivalent signature bit
- Parser/framing/capture flags
- Request-correlation status
- Whether inspection completed or was stopped after a match

Detection events should contain enough metadata to correlate the detection with the active request when the tracker is reliable:
- Process/thread context
- SSL pointer
- Request sequence when known
- First matching signature
- `is_malicious = true`
- Correlation status

The standalone detection event and final request event must not accidentally become two completed request records in `dataset.jsonl`. Use explicit event types or separate processing paths.

Keep the existing connection-level telemetry only if it remains accurate and clearly distinct from per-request verdicts.

### Go-side behavior

Update `main.go` to:
- Decode the updated event layouts correctly.
- Log first-match detections.
- Preserve malicious detections even when parser/framing flags are also present.
- Avoid dropping an event just because `Flags != 0` when that event contains a malicious verdict.
- Write completed request records to `dataset.jsonl` without duplicating immediate detection events as completed requests.
- Include the first matched signature and an explicit tracking/inspection status.
- Avoid writing plaintext request bodies into logs or datasets.

Check structure alignment and padding between C and Go. Do not assume binary layouts match automatically.

## 9. Preserve eBPF Safety and Runtime Stability

- Keep loops bounded and verifier-friendly.
- Do not add unbounded scanning loops.
- Do not put large arrays on the BPF stack.
- Keep persistent state in appropriate BPF maps.
- Preserve per-SSL cleanup in `SSL_free()`.
- Audit TTL handling so tracker and scanner state cannot become inconsistent.
- Handle ring-buffer output failures explicitly.
- Preserve the current signature patterns unless a separate bug is identified and explained.
- Do not silently convert malformed, incomplete, oversized, or unsupported requests into benign requests.

If a parser diagnostic is emitted after a signature has matched, include the already-established malicious verdict and signature metadata wherever possible.

## 10. Required Test Cases

Use unit tests for byte-processing/framing logic where feasible, plus integration tests against the local authorized test environment.

Test at least the following:

1. A normal GET request with no signature.
2. A request containing exactly one configured signature.
3. Confirm that one signature immediately sets `is_malicious = true` without waiting for composite rules.
4. Verify that further signature matching stops for that request after its first match.
5. A malicious request followed by a benign request on the same SSL connection.
6. Two complete requests delivered in one `SSL_read()` result.
7. One request spanning multiple `SSL_read()` calls.
8. A signature split across two chunks.
9. A signature occurring near the end of a 4096-byte chunk.
10. A single `SSL_read()` result larger than 4096 bytes, verifying that the remaining safe bytes are also processed.
11. A request larger than 8192 bytes with a signature beyond the old limit.
12. A long header exceeding the former 256-byte line limit.
13. A request with valid `Content-Length`.
14. Unsupported chunked framing, confirming that scanning remains active and correlation status is honest.
15. A capture/tracking error occurring before and after a signature match.
16. Ring-buffer output failure, parser-state recovery, and SSL object cleanup.
17. `poc-2.xml` using the authorized local test environment.

For the PoC regression test, verify that a configured signature found in its decrypted request causes a malicious detection event, even if the request tracker also reports an error. Confirm that no unrelated request on the same connection inherits that malicious verdict.

Do not treat test input length alone as proof of which parser limit was hit. Log or test the actual diagnostic reason.

## 11. Build and Validation

Use the repository's supported build process. The current `rebuild.sh` runs `go generate` and then builds `ssl-sniffer`.

After changes:
1. Regenerate BPF-generated Go files using the existing `go:generate` workflow.
2. Compile the eBPF program.
3. Load the program and validate it with the kernel verifier in the available test environment.
4. Build the Go executable.
5. Validate C/Go event structure sizes and field offsets.
6. Run the focused tests and report actual results.
7. Review `git diff` to ensure the change is scoped and does not include accidental dataset, binary, or unrelated generated changes.

Do not manually edit generated BPF files unless the repository's generation workflow requires it.

## 12. Deliverables

Provide:
1. A concise explanation of the current coupling bugs and their fixes.
2. The modified source files.
3. A description of how scanning remains active when request tracking fails.
4. A description of first-match early-exit semantics.
5. An explanation of large `SSL_read()` handling and the actual inspected-byte limits.
6. Build and verifier outcomes.
7. Test results, including the `poc-2.xml` regression test if it can be run.
8. Remaining limitations, especially unsupported HTTP framing and cases where request correlation cannot be guaranteed.

Inspect the actual implementation first. Then make the smallest coherent set of changes that satisfies these requirements. Do not claim that a test passed unless it was actually executed.
