# eBPF HTTPS WAF pre-filter

The SSL_read uretprobe reads decrypted plaintext into a per-CPU scratch buffer.
eBPF performs signature matching, rule evaluation, and verdict updates. A
separate raw-event ring buffer copies each available plaintext chunk to Go for
HTTP logging; file I/O and HTTP parsing stay in user space and do not affect
kernel verdicts.

## Rules

Put one YAML file per rule in rules/. The loader validates all files in sorted
filename order before populating the BPF maps. Patterns are ASCII literals,
limited to 24 bytes. Each rule may contain up to 32 signatures, with at most
32 rules and 32 total runtime signatures. The loader compiles enabled literal
signatures into separate case-sensitive and ASCII-folded Aho-Corasick
transition tables. Each automaton is limited to 512 states. Only the `any`
operator is supported; `all` rules are rejected during rule loading because
kernel verdict evaluation must remain bounded and verifier-safe.

The bundled OJS-FILE-001.yaml and OJS-TRAVERSAL-001.yaml contain the existing
PHP/upload and path-traversal literals. Disabled rules are validated but are
not evaluated. For case-insensitive patterns, matching uses ASCII lowercasing
only.

## Detection and request identity

The eBPF scanner advances two automaton states per byte using precompiled map
transitions, one for exact patterns and one for ASCII case-insensitive patterns.
Each transition carries the matching signature bits, rule bits, and legacy
verdict category bits, so the kernel callback does not scan a rule list or
compare each pattern byte. Matcher state is cleared at each request boundary.
A matching enabled rule immediately writes a malicious verdict; scanning
continues to the HTTP boundary to collect further matches.

The Nginx verdict map key/value layout is unchanged. The first_signature
field retains the existing category bits used by the Nginx policy; detailed
runtime signature and rule bitsets are carried in request events and translated
back to YAML IDs by Go. Adding a new rule does not automatically add its
signature category to the Nginx rejection policy.

## HTTP logging

Go reassembles raw_events by (TGID, SSL pointer, read_sequence, chunk_index)
and parses HTTP/1.1 requests framed by Content-Length. It preserves header
order and duplicates and supports multiple requests per read. Kernel request
events and parsed requests are joined only by (TGID, SSL pointer,
request_sequence). A gap, truncation, unsupported framing, or unknown
correlation is reported as incomplete/unsupported; the parser does not infer
request boundaries from timestamps or URIs.

The logger creates logs/requests.jsonl and logs/malicious.log at startup.
Requests contain parsed method, URI, version, ordered headers, and a body when
present. Valid UTF-8 bodies are logged as text; other bodies are Base64.
Sensitive headers and common password/token/secret/API-key fields in JSON or
form bodies are redacted in a logging copy. Generic body redaction can miss
application-specific secrets or redact harmless fields. Detection always uses
the original plaintext.

malicious.log has one text line per correlated malicious request. If events
cannot be correlated, the detection is retained with unknown sequence and
request metadata may be unavailable. Files are buffered, created with 0600
permissions in a 0700 directory, and rotated at about 64 MiB with five backups.

The raw ring buffer uses a fixed 4096-byte payload per event and a 16 MiB
capacity. Raw-event drops are counted separately and never block or change
eBPF inspection/enforcement. A lost chunk makes Go correlation unknown. Each
SSL_read is processed by eBPF in up to four 4096-byte chunks (16 KiB);
larger results and user-memory read failures are marked capture-incomplete.
The parser supports HTTP/1.1 with a single valid Content-Length; chunked
transfer encoding, HTTP/2, and malformed framing remain unsupported.
Go caps an individual buffered stream/request at 16 MiB; larger bodies are
logged as incomplete rather than buffered without limit. When the host enforces
RLIMIT_MEMLOCK, launch with a limit large enough for the BPF maps, including the
16 MiB raw ring buffer.

Run with ./ssl-sniffer -rules ./rules. Set EBPF_WAF_RULES_DIR to choose a
different rule directory.

## Request-level enforcement prototype

The standalone module in nginx/ reads verdicts from the pinned map and can
apply HTTP-level rejection after the request body has been buffered. observe
is the default; reject returns HTTP 403 only for reliable, complete
TRAVERSAL_RAW or TRAVERSAL_XML_ENTITY verdicts selected by policy.
FILE_NAME_TAG is not a blocking signature.

This prototype correlates TLS HTTP/1.1 requests using Nginx's per-connection
request count and the same SSL* exposed by its public headers. Chunked
requests, HTTP/2, and incomplete or uncertain tracking follow the configured
fallback. Keep HTTP/2 disabled on protected routes until the eBPF parser
supports it. See nginx/README.md for build, permissions, configuration, and
validation details. The live OJS Nginx configuration has not been changed or
reloaded.
