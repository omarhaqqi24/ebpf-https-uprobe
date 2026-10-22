# Implementation Plan: Kernel-Space HTTP/1.1 Per-Request Identification with eBPF

## 1. Context and Objective

I am developing an eBPF-based WAF prototype that observes decrypted HTTPS traffic from OpenSSL using uprobes.

Repository: `ebpf-https-uprobe`

Current architecture:
- `bpf/ssl.bpf.c`: eBPF C program attached to OpenSSL `SSL_read()`.
- `main.go`: Go userspace loader and event processor.
- Existing userspace code reconstructs HTTP requests from plaintext chunks and writes results to `dataset.jsonl`.
- The application being studied is Open Journal Systems (OJS), served through Nginx.
- The current research target uses HTTP/1.1.

The current implementation treats each `SSL_read()` result as a plaintext chunk. Go combines chunks, parses HTTP requests, and identifies request boundaries.

### Primary objective

Move HTTP/1.1 request-boundary identification and request sequence numbering into kernel space using eBPF C.

For this phase, implement identification only. Do not implement request blocking, Nginx enforcement, ML inference, or a complete WAF pipeline.

The desired result is that the eBPF program can distinguish multiple HTTP requests carried by the same TLS connection, even when:
1. A single HTTP request spans multiple `SSL_read()` calls.
2. One `SSL_read()` call contains multiple HTTP requests.
3. A request is incomplete when the current `SSL_read()` returns.

Go should receive request-identification events rather than performing the primary HTTP request-boundary parsing.

## 2. Inspect the Existing Repository First

Before modifying anything:

1. Inspect `bpf/ssl.bpf.c`, `main.go`, all BPF-generated Go files, build scripts, and module dependencies.
2. Identify the current entry probe and return probe for `SSL_read()`.
3. Identify how the entry probe records the SSL pointer, destination buffer address, and buffer capacity.
4. Identify how the return probe reads plaintext and submits events through the ring buffer.
5. Inspect the existing `RequestKey`, `RequestBuffer`, `parseHTTPRequest()`, and `parseRequestLoop()` implementations.
6. Check the existing signature detector and `dataset.jsonl` output format.
7. Identify the current build process, including `bpf2go`, compiler flags, and generated artifacts.
8. Determine which OpenSSL library and symbols are actually used by the target Nginx worker process.

Do not assume the existing code matches this description exactly. Verify the actual source code before planning modifications.

Preserve the current working functionality wherever possible. Do not rewrite the entire project.

## 3. Target Architecture

Implement the following data path:

```text
Nginx / OpenSSL
       |
       v
SSL_read() entry uprobe
       |
       | Save per-call metadata
       | keyed by PID/TID
       v
SSL_read() return uprobe
       |
       | Read actual return value
       | Copy valid plaintext bytes
       v
Per-connection eBPF parser state
       |
       | Append bytes incrementally
       | Parse HTTP/1.1 boundaries
       | Assign request sequence
       v
BPF ring buffer
       |
       | Emit one event per identified request
       v
Go userspace
       |
       | Receive structured events
       | Log and write dataset.jsonl
       v
Request identification results
```

The kernel-space parser must maintain state across `SSL_read()` calls. Do not equate a probe invocation with an HTTP request.

## 4. Design the eBPF Data Structures

Use separate structures for in-flight function calls, connection state, and emitted events.

### A. In-flight SSL_read state

Use a BPF hash map keyed by `bpf_get_current_pid_tgid()` or an equivalent PID/TID key.

Store:
- Process and thread identity if needed.
- `SSL *` pointer.
- Destination buffer address.
- Buffer capacity.

At function return:
- Retrieve and remove the matching in-flight state.
- Check the return value.
- Ignore non-positive return values.
- Read no more than the actual positive return value or the available destination capacity.
- Delete temporary state on every applicable exit path.

Do not assume that the destination buffer is always the same between calls.

### B. Persistent connection state

Use a BPF hash map keyed by a connection key such as:

```c
struct connection_key {
    __u32 tgid;
    __u64 ssl_ptr;
};
```

This key identifies an SSL object within a process. Do not include TID in the persistent connection key, because thread identity is not connection identity.

Store:
- A monotonically increasing request sequence number.
- The current parser state.
- The accumulated request data needed for parsing.
- The number of bytes currently buffered.
- The expected request length when known.
- Parser error or unsupported-framing status.

Use fixed-size buffers with explicit limits. Choose a practical initial maximum request size, such as 8192 bytes, after checking verifier constraints and expected OJS traffic.

If the implementation requires separate limits for headers and bodies, define them explicitly.

Do not use unbounded allocation or large temporary stack arrays.

### C. Request identification event

Define a compact event structure containing at least:

```c
struct request_event {
    __u32 tgid;
    __u64 ssl_ptr;
    __u64 request_sequence;
    __u64 timestamp_ns;

    __u32 request_length;
    __u16 method_length;
    __u16 uri_length;
    __u16 http_version_length;
    __u16 flags;

    char method[16];
    char uri[256];
    char http_version[16];
};
```

This is a proposed schema, not a requirement to copy it literally. Adjust field sizes and alignment as needed.

The event must identify one request, not one `SSL_read()` invocation.

If a request cannot be identified safely, emit a separate diagnostic event or increment an error counter rather than inventing a request sequence.

Do not emit plaintext credentials or full request bodies by default.

## 5. Implement an Incremental HTTP/1.1 Parser in eBPF C

Implement a bounded state machine that can resume parsing when another plaintext chunk arrives.

### Required parsing behavior

1. Recognize the request line:
   `METHOD SP REQUEST_TARGET SP HTTP/1.1 CRLF`

2. Recognize the end of headers:
   `CRLF CRLF`

3. Parse `Content-Length` when present.

4. For requests without a body, identify completion after the header terminator.

5. For requests with `Content-Length: N`, identify completion only after all N body bytes have been accumulated or accounted for.

6. Support multiple complete requests in one accumulated plaintext buffer.

7. Preserve incomplete request data for subsequent `SSL_read()` results.

8. Correctly handle boundaries split across chunks, including:
   - The request line.
   - Header lines.
   - The `CRLF CRLF` terminator.
   - The `Content-Length` value.
   - The body.

9. Once a request is complete:
   - Increment the connection's request sequence exactly once.
   - Emit one request event.
   - Advance the parser to the next request if additional bytes are present.
   - Preserve any trailing incomplete request data.

10. Use bounded loops and verifier-friendly logic. Avoid unbounded string functions and unchecked pointer arithmetic.

### HTTP framing rules

Implement the first version for HTTP/1.1 requests with:
- No body.
- A valid `Content-Length` body.

Do not silently interpret a request with `Transfer-Encoding: chunked` as a bodyless request.

For the first version, either implement chunked framing correctly or explicitly mark it unsupported and prevent the parser from falsely identifying subsequent body bytes as a new request. Document the chosen behavior.

Handle malformed or conflicting framing conservatively. Rejecting or flagging unsupported input for observation purposes is preferable to generating incorrect request boundaries.

Do not attempt to implement the complete HTTP specification in one pass.

## 6. Request Sequence Semantics

The request sequence belongs to the persistent connection state.

Example:

```text
Connection A:
    Request 1
    Request 2
    Request 3

Connection B:
    Request 1
    Request 2
```

If one `SSL_read()` returns two complete requests, emit two events with consecutive sequence numbers.

If three `SSL_read()` calls collectively contain one request, emit one event only after that request is complete.

Do not increment the sequence:
- At `SSL_read()` entry.
- At every `SSL_read()` return.
- When only a partial request line is available.
- When an incomplete request body has been received.

Use the tuple `(tgid, ssl_ptr, request_sequence)` as the initial correlation identifier.

Treat the SSL pointer as a connection-scoped identifier, not a permanent globally unique ID. Investigate cleanup when an SSL object is destroyed, including a suitable `SSL_free()` probe if feasible. Ensure pointer reuse cannot silently inherit stale parser state.

## 7. Buffer Limits and Error Handling

The existing implementation uses a fixed maximum event payload. Inspect the actual value before modifying it.

Important requirements:

1. Never assume the entire return value fits in the event payload.
2. Never read more bytes than the valid plaintext length.
3. Never silently truncate a chunk and continue as if the request were complete.
4. If a request exceeds the configured maximum, increment an error counter or emit a diagnostic event.
5. Ensure an oversized or malformed request cannot permanently desynchronize parsing for that connection.
6. Track ring-buffer reservation or submission failures.
7. Track map lookup, map update, and user-memory read failures where practical.
8. Avoid deleting persistent connection state simply because one request has completed.

For an initial implementation, explicit failure reporting is preferable to silently producing incorrect request IDs.

## 8. Go Userspace Changes

Modify `main.go` to consume the new kernel-generated request events.

Responsibilities of Go:
- Load and attach the eBPF programs.
- Read structured events from the ring buffer.
- Decode the request event.
- Log the connection key, sequence, method, URI, and HTTP version.
- Write one JSON object per identified request to `dataset.jsonl`.
- Report parser errors, unsupported framing, lost events, and buffer-limit violations.
- Preserve existing signature detection functionality if it can be done without duplicating request parsing.

Remove the primary HTTP request-boundary parsing from the normal event path only after kernel-space identification has been validated.

Do not remove useful legacy code prematurely. If necessary, retain it behind a temporary comparison mode for testing.

Do not treat the Go event consumer as the authoritative request parser in the final design.

## 9. Testing Plan

Create repeatable tests using a local TLS-enabled Nginx instance or another controlled TLS server using the same OpenSSL instrumentation path.

### Test A — Single request

Send one HTTP/1.1 GET request.

Expected:
- Exactly one request event.
- Sequence number 1.
- Correct method, URI, and HTTP version.

### Test B — Multiple requests on one connection

Send three HTTP/1.1 requests sequentially over one persistent connection.

Expected:
- Exactly three request events.
- Sequence numbers 1, 2, and 3.
- The same connection key for all three events.

Use a client that explicitly reuses the same connection. Do not assume separate `curl` invocations reuse connections.

### Test C — Multiple requests in one SSL_read result

Attempt to deliver multiple HTTP requests in a way that allows the application to read them together.

Expected:
- The parser emits one event per complete request, regardless of event boundaries.

Do not assume the operating system or OpenSSL will always produce a particular chunking pattern. Record the actual observed behavior.

### Test D — One request across multiple SSL_read calls

Split the request line, headers, and body across multiple writes from a controlled client.

Expected:
- No premature event.
- Exactly one event after the request is complete.

### Test E — Content-Length body

Send a POST request with a non-empty body.

Expected:
- The parser does not identify the next request before consuming the declared body length.

### Test F — Multiple requests plus a partial trailing request

Provide one complete request followed by part of a second request.

Expected:
- One event for the first request.
- No event for the incomplete second request.
- The second request is completed correctly when the remaining bytes arrive.

### Test G — Oversized and malformed requests

Test a request that exceeds the configured maximum and malformed framing.

Expected:
- Explicit error or unsupported-input reporting.
- No silent truncation presented as a valid complete request.
- No incorrect request sequence for unrecognized data.

### Test H — Regression

Verify that:
- The program builds.
- Existing attachment logic still works.
- Ring-buffer events are decoded correctly.
- Dataset output remains valid JSONL.
- The signature detector continues to work if it is retained in this phase.

Provide test scripts or a reproducible test procedure where practical.

## 10. Performance Considerations

The goal is to reduce userspace parsing overhead, not to assume that kernel parsing will automatically be faster.

Avoid:
- Sending every plaintext chunk to Go if it is no longer needed there.
- Copying the entire accumulated request into multiple temporary buffers.
- Scanning the complete accumulated request from byte zero after every new chunk.
- Large stack allocations.
- Excessive ring-buffer events.

Prefer an incremental state machine that processes new bytes while retaining the necessary parser state.

If feasible, collect counters for:
- Number of `SSL_read()` calls.
- Number of plaintext bytes observed.
- Number of complete requests identified.
- Number of parser errors.
- Number of oversized requests.
- Number of lost or failed events.

Performance benchmarking is secondary to correctness in this phase.

## 11. Implementation Workflow

Work incrementally:

1. Inspect and summarize the existing code.
2. Propose the smallest architecture change.
3. Implement kernel-side state and request parsing.
4. Update the event structure and regenerate BPF bindings using the existing build workflow.
5. Update Go to consume request events.
6. Build the project and fix compiler/verifier errors.
7. Run the tests and verify the emitted request sequences.
8. Check cleanup, buffer limits, and error reporting.
9. Summarize changed files and provide the exact commands used to build and test.

Do not claim success based only on compilation. Demonstrate that multiple requests on one persistent connection are identified correctly.

Do not modify unrelated project files, change the research scope, or implement Nginx blocking during this phase.

## 12. Definition of Done

The implementation is complete when all of the following are true:

- [ ] HTTP/1.1 request-boundary identification runs in eBPF C.
- [ ] Request sequence numbers are generated in kernel space.
- [ ] Multiple requests on one TLS connection receive distinct, consecutive sequence numbers.
- [ ] A request spanning multiple `SSL_read()` calls produces one request event.
- [ ] Multiple requests contained in one accumulated plaintext sequence produce separate events.
- [ ] Partial requests do not produce premature request events.
- [ ] `Content-Length` framing works correctly within configured limits.
- [ ] Unsupported framing and oversized requests are reported explicitly.
- [ ] Go receives structured per-request events without being responsible for primary request-boundary parsing.
- [ ] The project builds and passes the reproducible integration tests.
- [ ] The final report identifies any remaining limitations and provides the exact test commands.

Start by inspecting the repository. Report your findings and the proposed minimal changes before making substantial modifications.
