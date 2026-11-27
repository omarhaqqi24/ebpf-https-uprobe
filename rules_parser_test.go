package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestRuleFilesCompileToRuntimeMaps(t *testing.T) {
	rules, sigs, configs, err := loadRules("rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 || len(sigs) != 17 || len(configs) != 4 {
		t.Fatalf("unexpected compiled config: rules=%d signatures=%d", len(rules), len(sigs))
	}
	for i, sig := range sigs {
		if sig.PatternLen > maxPatternBytes {
			t.Fatalf("signature %d has invalid pattern length %d", i, sig.PatternLen)
		}
		if sig.PatternLen != 0 && sig.VerdictMask == 0 {
			t.Fatalf("configured literal signature %d has no verdict category", i)
		}
	}
}

func TestCompiledAutomatonMatchesExactAndFoldedPatterns(t *testing.T) {
	match := func(transitions map[uint32]runtimeAutomatonTransition, input []byte) (uint32, uint32, uint32) {
		var exactState, foldedState uint32
		var signatures, rules, flags uint32
		for _, char := range input {
			exact := transitions[exactState*256+uint32(char)]
			exactState = exact.NextState
			foldKey := (512+foldedState)*256 + uint32(asciiLower(char))
			folded := transitions[foldKey]
			foldedState = folded.NextState
			signatures |= exact.Matches | folded.Matches
			rules |= exact.Rules | folded.Rules
			flags |= exact.Flags | folded.Flags
		}
		return signatures, rules, flags
	}

	rules, _, _, err := loadRules("rules")
	if err != nil {
		t.Fatal(err)
	}
	transitions, err := buildAutomatonTransitions(rules)
	if err != nil {
		t.Fatal(err)
	}
	signatures, matchedRules, flags := match(transitions, []byte("POST /upload text/x-php"))
	if signatures&(1<<3) == 0 || matchedRules&(1<<2) == 0 || flags&1 == 0 {
		t.Fatalf("exact signature output missing: signatures=%032b rules=%032b flags=%032b", signatures, matchedRules, flags)
	}

	dir := t.TempDir()
	content := "id: CASE-1\nname: Case check\nvulnerability: test_rule\nenabled: true\nsignatures:\n  - id: FOLDED\n    pattern: 'AbC'\n    case_sensitive: false\n"
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	foldRules, _, _, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	foldTransitions, err := buildAutomatonTransitions(foldRules)
	if err != nil {
		t.Fatal(err)
	}
	signatures, matchedRules, _ = match(foldTransitions, []byte("zABC"))
	if signatures&1 == 0 || matchedRules&1 == 0 {
		t.Fatalf("case-insensitive signature output missing: signatures=%032b rules=%032b", signatures, matchedRules)
	}
}

func TestRuleLoaderRejectsRemovedOperatorAndInvalidPattern(t *testing.T) {
	for _, content := range []string{
		"id: TEST\nname: Test\nvulnerability: test_rule\nenabled: true\nmatch:\n  operator: any\nsignatures:\n  - id: X\n    pattern: x\n",
		fmt.Sprintf("id: TEST\nname: Test\nvulnerability: test_rule\nenabled: true\nsignatures:\n  - id: X\n    pattern: %q\n", strings.Repeat("x", maxPatternBytes+1)),
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := loadRules(dir); err == nil {
			t.Fatalf("invalid rule accepted: %s", content)
		}
	}
}

func TestHTTPParserCompleteCombinedAndPartial(t *testing.T) {
	input := []byte("GET /one HTTP/1.1\r\nHost: example.test\r\nX-Repeat: a\r\nX-Repeat: b\r\n\r\nPOST /two HTTP/1.1\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\ndata")
	parsed, consumed, bad := parseHTTPRequests(input, 1, time.Unix(0, 0).UTC(), true)
	if bad || len(parsed) != 2 || consumed != len(input) {
		t.Fatalf("combined parse failed: count=%d consumed=%d bad=%t", len(parsed), consumed, bad)
	}
	if parsed[0].Sequence != 1 || len(parsed[0].Headers) != 3 || parsed[0].Headers[1].Value != "a" || parsed[0].Headers[2].Value != "b" {
		t.Fatalf("ordered duplicate headers lost: %+v", parsed[0])
	}
	if parsed[1].Sequence != 2 || string(parsed[1].Body) != "data" || !parsed[1].Complete {
		t.Fatalf("POST body not parsed: %+v", parsed[1])
	}
	prefix := input[:len(input)-2]
	partial, partialConsumed, partialBad := parseHTTPRequests(prefix, 1, time.Now(), true)
	if len(partial) != 1 || partialConsumed == 0 || partialBad {
		t.Fatalf("complete first request should survive partial second: count=%d consumed=%d bad=%t", len(partial), partialConsumed, partialBad)
	}
}

func TestHTTPParserRejectsUnsupportedAndDuplicateLength(t *testing.T) {
	unsupported := []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
	reqs, _, bad := parseHTTPRequests(unsupported, 1, time.Now(), true)
	if !bad || len(reqs) != 1 || !reqs[0].Unsupported {
		t.Fatalf("chunked framing not marked unsupported: %+v bad=%t", reqs, bad)
	}
	duplicate := []byte("POST / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\na")
	_, _, bad = parseHTTPRequests(duplicate, 1, time.Now(), true)
	if !bad {
		t.Fatal("duplicate Content-Length was not rejected")
	}
	plusLength := []byte("POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\na")
	_, _, bad = parseHTTPRequests(plusLength, 1, time.Now(), true)
	if !bad {
		t.Fatal("Content-Length syntax diverging from the eBPF parser was accepted")
	}
}

func TestHTTPParserNoHeadersAndTruncatedBody(t *testing.T) {
	get := []byte("GET / HTTP/1.1\r\n\r\n")
	parsed, consumed, bad := parseHTTPRequests(get, 1, time.Now(), true)
	if bad || len(parsed) != 1 || consumed != len(get) {
		t.Fatalf("headerless GET failed: parsed=%d consumed=%d bad=%t", len(parsed), consumed, bad)
	}
	body := []byte("POST /upload HTTP/1.1\r\nContent-Length: 4\r\n\r\nab")
	parsed, _, bad = parseHTTPRequests(body, 1, time.Now(), true)
	if bad || len(parsed) != 0 {
		t.Fatalf("partial body was presented as complete: parsed=%d bad=%t", len(parsed), bad)
	}
	partial := parsePartialHTTPRequest(body, 1, time.Now(), "capture_truncated")
	if partial.Complete || string(partial.Body) != "ab" || partial.ExpectedBody != 4 {
		t.Fatalf("partial body metadata lost: %+v", partial)
	}
}

func TestEventAndMapABI(t *testing.T) {
	if got := binary.Size(RequestEvent{}); got != 368 {
		t.Fatalf("request event ABI size=%d, want 368", got)
	}
	if got := binary.Size(RawChunkEvent{}); got != 4160 {
		t.Fatalf("raw event ABI size=%d, want 4160", got)
	}
	if got := binary.Size(runtimeSignature{}); got != 36 {
		t.Fatalf("signature map value size=%d, want 36", got)
	}
	if got := binary.Size(runtimeAutomatonTransition{}); got != 16 {
		t.Fatalf("automaton transition value size=%d, want 16", got)
	}
	if got := binary.Size(runtimeRule{}); got != 8 {
		t.Fatalf("rule map value size=%d, want 8", got)
	}
	if got := binary.Size(RequestCounters{}); got != 120 {
		t.Fatalf("request counter map value size=%d, want 120", got)
	}
}

func TestScopedMatcherRepeatAndHeaderScope(t *testing.T) {
	rules, _, _, err := loadRules("rules")
	if err != nil {
		t.Fatal(err)
	}
	trans, err := buildScopedTransitions(rules)
	if err != nil {
		t.Fatal(err)
	}
	scopeIDs, err := scopeIDMap(rules)
	if err != nil {
		t.Fatal(err)
	}
	run := func(scope scopeKey, v []byte) (uint32, uint32) {
		var st uint32
		var sigs, rm uint32
		for _, b := range v {
			tr := trans[(scopeIDs[scope]*maxScopedStates+st)*256+uint32(b)]
			st = tr.NextState
			sigs |= tr.Matches
			rm |= tr.Rules
		}
		return sigs, rm
	}
	positives := []string{"'; @import(inline) '/x'", "'; @import 	 (  inline	 ) '/x'", "';" + strings.Repeat(" ", 1024) + "@import" + strings.Repeat("\t", 64) + "(" + strings.Repeat(" ", 8) + "inline" + strings.Repeat("\t", 256) + ")"}
	for _, v := range positives {
		s, r := run(scopeKey{"http_header_value", "x-forwarded-host"}, []byte(v))
		if s&1 == 0 || r&1 == 0 {
			t.Errorf("inline import missed: %x/%x", s, r)
		}
	}
	data := "'; body { background: data-uri('/etc/passwd'); } //"
	s, r := run(scopeKey{"http_header_value", "x-forwarded-host"}, []byte(data))
	if s&2 == 0 || r&1 == 0 {
		t.Fatalf("data-uri missed: %x/%x", s, r)
	}
	negatives := []string{"journals.example.org", "@import (inline)", "'; @import url('/x')", "'; body { background: url(x); }"}
	for _, v := range negatives {
		s, r := run(scopeKey{"http_header_value", "x-forwarded-host"}, []byte(v))
		if s != 0 || r != 0 {
			t.Errorf("unexpected match: %q %x/%x", v, s, r)
		}
	}
	body := []byte("1;++++++@import+++++++++(inline)+++'")
	bs, br := run(scopeKey{"http_body_parameter", "baseColour"}, body)
	if bs&(1<<2) == 0 || br&(1<<1) == 0 {
		t.Fatalf("raw baseColour token sequence missed: %x/%x", bs, br)
	}
	for _, bad := range [][]byte{[]byte("1;@import+++(inline)+++'"), []byte("1;++++++@import+++++++++(inline)++%2B+'"), []byte("1;++++++@import+++++++++(inline)++%2B+'")} {
		s, r := run(scopeKey{"http_body_parameter", "baseColour"}, bad)
		if s&(1<<2) != 0 || r&(1<<1) != 0 {
			t.Errorf("unexpected body match %q: %x/%x", bad, s, r)
		}
	}
}

func TestRepeatTokenSemanticsAndDynamicScopeIsolation(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"one.yaml": `id: R1
name: Repeat one
vulnerability: test_rule
enabled: true
match:
  scope:
    type: http_body_parameter
    name: themeName
signatures:
  - id: S1
    matcher:
      tokens:
        - literal: A
        - repeat:
            chars: ["x"]
            min: 2
            max: 4
        - literal: B
`,
		"two.yaml": `id: R2
name: Repeat exact
vulnerability: test_rule
enabled: true
match:
  scope:
    type: http_header_value
    name: X-Custom
signatures:
  - id: S2
    matcher:
      tokens:
        - literal: A
        - repeat:
            chars: ["."]
            min: 2
            max: 2
        - literal: B
`,
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rules, _, _, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rules[1].Match.Scope.Name != "x-custom" {
		t.Fatalf("header scope was not canonicalized: %+v", rules[1].Match.Scope)
	}
	trans, err := buildScopedTransitions(rules)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := scopeIDMap(rules)
	if err != nil {
		t.Fatal(err)
	}
	run := func(scope scopeKey, input string) uint32 {
		st := uint32(0)
		var matches uint32
		for _, b := range []byte(input) {
			tr := trans[(ids[scope]*maxScopedStates+st)*256+uint32(b)]
			st = tr.NextState
			matches |= tr.Matches
		}
		return matches
	}
	body := scopeKey{"http_body_parameter", "themeName"}
	header := scopeKey{"http_header_value", "x-custom"}
	if run(body, "AxxB")&1 == 0 || run(body, "AxxxxB")&1 == 0 {
		t.Fatal("bounded repeat failed within [min,max]")
	}
	if run(body, "AxB")&1 != 0 || run(body, "AxxxxxB")&1 != 0 {
		t.Fatal("bounded repeat accepted outside [min,max]")
	}
	if run(header, "A..B")&2 == 0 || run(header, "A.B")&2 != 0 || run(header, "AxxB")&2 != 0 {
		t.Fatal("exact repeat or scope isolation failed")
	}
	if run(body, "A..B")&2 != 0 || run(header, "AxxB")&1 != 0 {
		t.Fatal("matcher output leaked across scope IDs")
	}
}

func TestRepeatZeroMinimumUnboundedAndRuleSchemaValidation(t *testing.T) {
	dir := t.TempDir()
	content := `id: UNBOUND
name: Repeat unbounded
vulnerability: test_rule
enabled: true
match:
  scope:
    type: http_body_parameter
    name: q
signatures:
  - id: S
    matcher:
      tokens:
        - literal: A
        - repeat:
            chars: [".", "+", " ", "\t"]
            min: 0
        - literal: B
`
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	rules, _, _, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	trans, err := buildScopedTransitions(rules)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := scopeIDMap(rules)
	run := func(v string) bool {
		st := uint32(0)
		var matched uint32
		for _, b := range []byte(v) {
			tr := trans[(ids[scopeKey{"http_body_parameter", "q"}]*maxScopedStates+st)*256+uint32(b)]
			st = tr.NextState
			matched |= tr.Matches
		}
		return matched&1 != 0
	}
	for _, v := range []string{"AB", "A...B", "A++ B", "A.\tB"} {
		if !run(v) {
			t.Errorf("unbounded/zero-min repeat missed %q", v)
		}
	}
	invalid := []string{
		strings.Replace(content, "    name: q\n", "    name: q\n  operator: any\n", 1),
		strings.Replace(content, "      tokens:\n", "      type: token_sequence\n      tokens:\n", 1),
		strings.Replace(content, "      tokens:\n", "      case_sensitive: true\n      tokens:\n", 1),
		strings.Replace(content, "        - repeat:\n", "        - hws:\n            quantifier: zero_or_more\n", 1),
	}
	for _, bad := range invalid {
		testDir := t.TempDir()
		if e := os.WriteFile(filepath.Join(testDir, "bad.yaml"), []byte(bad), 0600); e != nil {
			t.Fatal(e)
		}
		if _, _, _, e := loadRules(testDir); e == nil {
			t.Errorf("removed/unknown schema field was accepted")
		}
	}
}

func TestBodyScopeNamesAreExactAndDynamic(t *testing.T) {
	dir := t.TempDir()
	for i, name := range []string{"baseColour", "BaseColour"} {
		c := fmt.Sprintf("id: R%d\nname: Scope %d\nvulnerability: test_rule\nenabled: true\nmatch:\n  scope:\n    type: http_body_parameter\n    name: %s\nsignatures:\n  - id: S%d\n    matcher:\n      tokens:\n        - literal: X\n", i, i, name, i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.yaml", i)), []byte(c), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rules, _, _, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := scopeIDMap(rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[scopeKey{"http_body_parameter", "baseColour"}] == ids[scopeKey{"http_body_parameter", "BaseColour"}] {
		t.Fatalf("body scope names are not distinct/exact: %#v", ids)
	}
}

func TestKernelBPFStartupMaps(t *testing.T) {
	if os.Getenv("EBPF_WAF_KERNEL_TEST") != "1" {
		t.Skip("set EBPF_WAF_KERNEL_TEST=1 to load BPF programs without attaching probes")
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load BPF collection: %v", err)
	}
	defer objs.Close()
	if objs.ScopeRegistry.KeySize() != uint32(binary.Size(runtimeScopeKey{})) || objs.ScopeRegistry.ValueSize() != 4 {
		t.Fatalf("scope registry ABI mismatch: %d/%d", objs.ScopeRegistry.KeySize(), objs.ScopeRegistry.ValueSize())
	}
	if err := applyRules("rules", objs.SignaturePatterns, objs.RuleConfigs, objs.AutomatonTransitions, objs.ScopedTransitions, objs.ScopeRegistry); err != nil {
		t.Fatalf("load rule and scope maps: %v", err)
	}
	key := uint32(0)
	fd := uint32(objs.SslParseStep.FD())
	if err := objs.ParserPrograms.Update(&key, fd, ebpf.UpdateAny); err != nil {
		t.Fatalf("install parser tail-call program: %v", err)
	}
}
