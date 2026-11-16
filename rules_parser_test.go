package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuleFilesCompileToRuntimeMaps(t *testing.T) {
	rules, sigs, configs, err := loadRules("rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || len(sigs) != 14 || len(configs) != 2 {
		t.Fatalf("unexpected compiled config: rules=%d signatures=%d", len(rules), len(sigs))
	}
	for i, sig := range sigs {
		if sig.PatternLen == 0 || sig.PatternLen > maxPatternBytes {
			t.Fatalf("signature %d has invalid pattern length %d", i, sig.PatternLen)
		}
		if sig.VerdictMask == 0 {
			t.Fatalf("configured OJS signature %d has no compatible verdict category", i)
		}
	}
	if configs[0].Operator != runtimeRuleAny || configs[1].Operator != runtimeRuleAny {
		t.Fatalf("unexpected rule operators: %+v", configs)
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
	if signatures&1 == 0 || matchedRules&1 == 0 || flags&1 == 0 {
		t.Fatalf("exact signature output missing: signatures=%032b rules=%032b flags=%032b", signatures, matchedRules, flags)
	}

	dir := t.TempDir()
	content := "id: CASE-1\nname: Case check\nvulnerability: test_rule\nenabled: true\nmatch:\n  operator: any\nsignatures:\n  - id: FOLDED\n    pattern: 'AbC'\n    case_sensitive: false\n"
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

func TestRuleLoaderRejectsInvalidLimits(t *testing.T) {
	for _, tc := range []struct {
		name, operator, pattern string
		signatures              int
	}{
		{name: "operator", operator: "xor", pattern: "x", signatures: 1},
		{name: "pattern length", operator: "any", pattern: strings.Repeat("x", maxPatternBytes+1), signatures: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var sigs strings.Builder
			for i := 0; i < tc.signatures; i++ {
				fmt.Fprintf(&sigs, "  - id: S%d\n    pattern: %q\n", i, tc.pattern)
			}
			body := fmt.Sprintf("id: TEST\nname: Test\nvulnerability: test_rule\nenabled: true\nmatch:\n  operator: %s\nsignatures:\n%s", tc.operator, sigs.String())
			if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := loadRules(dir); err == nil {
				t.Fatal("invalid rule configuration was accepted")
			}
		})
	}
}

func TestRuleLoaderRejectsAllOperatorForKernelAutomaton(t *testing.T) {
	dir := t.TempDir()
	content := "id: COMBO-1\nname: Combo\nvulnerability: test_rule\nenabled: true\nmatch:\n  operator: all\nsignatures:\n  - id: FIRST\n    pattern: \"ABC\"\n    case_sensitive: false\n  - id: SECOND\n    pattern: \"xyz\"\n"
	if err := os.WriteFile(filepath.Join(dir, "combo.yaml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadRules(dir); err == nil || !strings.Contains(err.Error(), "all is not supported") {
		t.Fatalf("unsupported all operator should be rejected explicitly, got %v", err)
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
