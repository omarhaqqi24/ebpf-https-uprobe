package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"
)

const (
	maxRuntimeSignatures = 32
	maxRuntimeRules      = 32
	maxPatternBytes      = 24
	maxScopes            = 16
	maxScopeName         = 64
	maxRepeatMax         = 64
	maxScopedStates      = 512
)

type RuleFile struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	Vulnerability string `yaml:"vulnerability"`
	Description   string `yaml:"description"`
	Enabled       *bool  `yaml:"enabled"`
	Severity      string `yaml:"severity"`
	Match         struct {
		Scope *RuleScope `yaml:"scope"`
	} `yaml:"match"`
	Signatures []RuleSignature `yaml:"signatures"`
}
type RuleScope struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}
type RuleSignature struct {
	ID            string             `yaml:"id"`
	Pattern       string             `yaml:"pattern"`
	CaseSensitive *bool              `yaml:"case_sensitive"`
	Matcher       *StructuredMatcher `yaml:"matcher"`
}
type StructuredMatcher struct {
	Tokens []MatcherToken `yaml:"tokens"`
}
type MatcherToken struct {
	Literal *string      `yaml:"literal"`
	Repeat  *RepeatToken `yaml:"repeat"`
}
type RepeatToken struct {
	Chars []string `yaml:"chars"`
	Min   *int     `yaml:"min"`
	Max   *int     `yaml:"max"`
}

type runtimeSignature struct {
	RuleIndex     uint32
	VerdictMask   uint32
	Enabled       uint8
	CaseSensitive uint8
	PatternLen    uint8
	Pad           uint8
	Pattern       [maxPatternBytes]byte
}
type runtimeRule struct {
	SignatureMask uint32
	Enabled       uint8
	Pad           [3]uint8
}
type runtimeAutomatonTransition struct {
	NextState uint32
	Matches   uint32
	Rules     uint32
	Flags     uint32
}
type automatonNode struct {
	next   map[byte]int
	fail   int
	output runtimeAutomatonTransition
}

var signatureLabels = map[uint32]string{}
var ruleLabels = map[uint32]string{}
var ruleSeverities = map[uint32]string{}
var vulnerabilityName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func loadRules(dir string) ([]RuleFile, []runtimeSignature, []runtimeRule, error) {
	signatureLabels = map[uint32]string{}
	ruleLabels = map[uint32]string{}
	ruleSeverities = map[uint32]string{}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, nil, nil, err
	}
	more, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, nil, nil, err
	}
	files = append(files, more...)
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil, nil, fmt.Errorf("no YAML rule files found in %s", dir)
	}
	rules := make([]RuleFile, 0, len(files))
	runtimeSigs := make([]runtimeSignature, 0, maxRuntimeSignatures)
	runtimeRules := make([]runtimeRule, 0, maxRuntimeRules)
	seenRules := map[string]bool{}
	seenSignatures := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		var rule RuleFile
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&rule); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		var extra any
		if err := dec.Decode(&extra); err == nil {
			return nil, nil, nil, fmt.Errorf("%s: multiple YAML documents are not allowed", file)
		} else if err != io.EOF {
			return nil, nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Vulnerability = strings.TrimSpace(rule.Vulnerability)
		if rule.ID == "" || seenRules[rule.ID] {
			return nil, nil, nil, fmt.Errorf("%s: id is empty or duplicated: %q", file, rule.ID)
		}
		if rule.Name == "" || !vulnerabilityName.MatchString(rule.Vulnerability) {
			return nil, nil, nil, fmt.Errorf("%s: name is required and vulnerability must be a lowercase category slug", file)
		}
		severity := strings.ToLower(strings.TrimSpace(rule.Severity))
		if severity != "" && severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
			return nil, nil, nil, fmt.Errorf("%s: severity must be low, medium, high, critical, or omitted", file)
		}
		if rule.Enabled == nil {
			return nil, nil, nil, fmt.Errorf("%s: enabled is required", file)
		}
		if rule.Match.Scope != nil {
			sc := rule.Match.Scope
			if (sc.Type != "http_header_value" && sc.Type != "http_body_parameter") || sc.Name == "" || len(sc.Name) > maxScopeName || !isASCII(sc.Name) {
				return nil, nil, nil, fmt.Errorf("%s: scope must use a supported type and an ASCII name of 1..%d bytes", file, maxScopeName)
			}
			if sc.Type == "http_header_value" {
				sc.Name = strings.ToLower(sc.Name)
			}
		}
		if len(rule.Signatures) == 0 || len(rule.Signatures) > maxRuntimeSignatures {
			return nil, nil, nil, fmt.Errorf("%s: signatures must contain 1..%d items", file, maxRuntimeSignatures)
		}
		if len(rules) >= maxRuntimeRules {
			return nil, nil, nil, fmt.Errorf("%s: exceeds %d rules", file, maxRuntimeRules)
		}
		seenRules[rule.ID] = true
		ruleIndex := uint32(len(rules))
		rules = append(rules, rule)
		rr := runtimeRule{Enabled: 1}
		if !*rule.Enabled {
			rr.Enabled = 0
		}
		localIDs := map[string]bool{}
		for _, item := range rule.Signatures {
			sigID := strings.TrimSpace(item.ID)
			if sigID == "" || localIDs[sigID] || seenSignatures[sigID] {
				return nil, nil, nil, fmt.Errorf("%s: signature id is empty or duplicated: %q", file, sigID)
			}
			localIDs[sigID] = true
			seenSignatures[sigID] = true
			if (item.Pattern == "") == (item.Matcher == nil) {
				return nil, nil, nil, fmt.Errorf("%s: signature %s must define exactly one of pattern or matcher", file, sigID)
			}
			pat := []byte(item.Pattern)
			if item.Matcher == nil {
				if len(pat) == 0 || len(pat) > maxPatternBytes {
					return nil, nil, nil, fmt.Errorf("%s: signature %s pattern length invalid", file, sigID)
				}
				for _, b := range pat {
					if b > 0x7f {
						return nil, nil, nil, fmt.Errorf("%s: pattern must be ASCII", file)
					}
				}
			} else if rule.Match.Scope == nil || len(item.Matcher.Tokens) == 0 {
				return nil, nil, nil, fmt.Errorf("%s: structured matcher needs a field scope for %s", file, sigID)
			} else {
				for _, t := range item.Matcher.Tokens {
					if (t.Literal == nil) == (t.Repeat == nil) {
						return nil, nil, nil, fmt.Errorf("%s: token must define exactly one of literal or repeat", file)
					}
					if t.Literal != nil && (*t.Literal == "" || !isASCII(*t.Literal)) {
						return nil, nil, nil, fmt.Errorf("%s: literal token must be non-empty ASCII", file)
					}
					if t.Repeat != nil {
						rt := t.Repeat
						if len(rt.Chars) == 0 || rt.Min == nil || *rt.Min < 0 {
							return nil, nil, nil, fmt.Errorf("%s: repeat requires chars and non-negative min", file)
						}
						seen := map[byte]bool{}
						for _, ch := range rt.Chars {
							if len(ch) != 1 || ch[0] > 127 || seen[ch[0]] {
								return nil, nil, nil, fmt.Errorf("%s: repeat chars must be distinct single-byte ASCII", file)
							}
							seen[ch[0]] = true
						}
						if rt.Max != nil && (*rt.Max < *rt.Min || *rt.Max > maxRepeatMax) {
							return nil, nil, nil, fmt.Errorf("%s: repeat max must be >= min and <= %d", file, maxRepeatMax)
						}
					}
				}
			}
			if len(runtimeSigs) >= maxRuntimeSignatures {
				return nil, nil, nil, fmt.Errorf("%s: exceeds %d total signatures", file, maxRuntimeSignatures)
			}
			cs := true
			if item.CaseSensitive != nil {
				cs = *item.CaseSensitive
			}
			sigIndex := uint32(len(runtimeSigs))
			bit := uint32(1) << sigIndex
			rs := runtimeSignature{RuleIndex: ruleIndex, Enabled: 1, PatternLen: uint8(len(pat)), CaseSensitive: 1}
			rs.VerdictMask = legacyVerdictMask(rule.Vulnerability, sigID, pat)
			if !*rule.Enabled {
				rs.Enabled = 0
			}
			if !cs {
				rs.CaseSensitive = 0
			}
			for i, b := range pat {
				rs.Pattern[len(pat)-1-i] = b
			}
			runtimeSigs = append(runtimeSigs, rs)
			rr.SignatureMask |= bit
			label := rule.ID + "/" + sigID
			signatureLabels[bit] = label

		}
		runtimeRules = append(runtimeRules, rr)
		ruleLabels[1<<ruleIndex] = rule.ID
		ruleSeverities[1<<ruleIndex] = rule.Severity
	}
	return rules, runtimeSigs, runtimeRules, nil
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func legacyVerdictMask(vulnerability, signatureID string, pattern []byte) uint32 {
	if strings.EqualFold(vulnerability, "less_code_injection") {
		return 1 << 7
	}
	if strings.EqualFold(vulnerability, "path_traversal") {
		if bytes.Contains(pattern, []byte("&")) {
			return 1 << 6
		}
		return 1 << 5
	}
	switch strings.ToLower(signatureID) {
	case "text-x-php":
		return 1 << 0
	case "embed-tag":
		return 1 << 1
	case "base64-attr-double-quoted":
		return 1 << 2
	case "base64-attr-single-quoted":
		return 1 << 3
	case "file-name-tag":
		return 1 << 4
	default:
		return 0
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

type scopeKey struct {
	Type string
	Name string
}
type runtimeScopeKey struct {
	PrefixLen uint32
	Kind      uint8
	NameLen   uint8
	Pad       uint16
	Name      [maxScopeName]byte
}

func makeRuntimeScopeKey(k scopeKey) runtimeScopeKey {
	var v runtimeScopeKey
	if k.Type == "http_header_value" {
		v.Kind = 1
	} else {
		v.Kind = 2
	}
	v.NameLen = uint8(len(k.Name))
	v.PrefixLen = uint32((4 + len(k.Name)) * 8)
	copy(v.Name[:], k.Name)
	return v
}
func scopeIDMap(rules []RuleFile) (map[scopeKey]uint32, error) {
	keys := map[scopeKey]bool{}
	for _, r := range rules {
		if r.Enabled != nil && *r.Enabled {
			for _, sig := range r.Signatures {
				if sig.Matcher != nil {
					k := scopeKey{r.Match.Scope.Type, r.Match.Scope.Name}
					keys[k] = true
				}
			}
		}
	}
	ordered := make([]scopeKey, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Type != ordered[j].Type {
			return ordered[i].Type < ordered[j].Type
		}
		return ordered[i].Name < ordered[j].Name
	})
	if len(ordered) > maxScopes {
		return nil, fmt.Errorf("configured structured scopes exceed %d", maxScopes)
	}
	ids := make(map[scopeKey]uint32, len(ordered))
	for i, k := range ordered {
		ids[k] = uint32(i + 1)
	}
	return ids, nil
}
func buildScopedTransitions(rules []RuleFile) (map[uint32]runtimeAutomatonTransition, error) {
	ids, err := scopeIDMap(rules)
	if err != nil {
		return nil, err
	}
	type node struct {
		edge   map[byte][]int
		eps    []int
		output runtimeAutomatonTransition
	}
	out := map[uint32]runtimeAutomatonTransition{}
	for scope, id := range ids {
		nodes := []node{{edge: map[byte][]int{}}}
		roots := []int{}
		for ri, r := range rules {
			if r.Enabled == nil || !*r.Enabled || r.Match.Scope == nil || r.Match.Scope.Type != scope.Type || r.Match.Scope.Name != scope.Name {
				continue
			}
			base := uint32(0)
			for j := 0; j < ri; j++ {
				base += uint32(len(rules[j].Signatures))
			}
			for si, sig := range r.Signatures {
				if sig.Matcher == nil {
					continue
				}
				root := len(nodes)
				roots = append(roots, root)
				nodes = append(nodes, node{edge: map[byte][]int{}})
				cur := root
				for _, tok := range sig.Matcher.Tokens {
					if tok.Literal != nil {
						for _, b := range []byte(*tok.Literal) {
							n := len(nodes)
							nodes = append(nodes, node{edge: map[byte][]int{}})
							nodes[cur].edge[b] = append(nodes[cur].edge[b], n)
							cur = n
						}
						continue
					}
					rt := tok.Repeat
					addSet := func(from, to int) {
						for _, ch := range rt.Chars {
							nodes[from].edge[ch[0]] = append(nodes[from].edge[ch[0]], to)
						}
					}
					for n := 0; n < *rt.Min; n++ {
						next := len(nodes)
						nodes = append(nodes, node{edge: map[byte][]int{}})
						addSet(cur, next)
						cur = next
					}
					if rt.Max == nil {
						loop := len(nodes)
						nodes = append(nodes, node{edge: map[byte][]int{}})
						nodes[cur].eps = append(nodes[cur].eps, loop)
						addSet(cur, cur)
						cur = loop
					} else {
						for n := *rt.Min; n < *rt.Max; n++ {
							next := len(nodes)
							nodes = append(nodes, node{edge: map[byte][]int{}})
							nodes[cur].eps = append(nodes[cur].eps, next)
							addSet(cur, next)
							cur = next
						}
						exit := len(nodes)
						nodes = append(nodes, node{edge: map[byte][]int{}})
						nodes[cur].eps = append(nodes[cur].eps, exit)
						cur = exit
					}
				}
				nodes[cur].output.Matches = 1 << (base + uint32(si))
				nodes[cur].output.Rules = 1 << uint32(ri)
				nodes[cur].output.Flags = legacyVerdictMask(r.Vulnerability, sig.ID, nil)
			}
		}
		if len(roots) == 0 {
			continue
		}
		closure := func(a []bool) {
			for again := true; again; {
				again = false
				for i, on := range a {
					if on {
						for _, n := range nodes[i].eps {
							if !a[n] {
								a[n] = true
								again = true
							}
						}
					}
				}
			}
		}
		key := func(a []bool) string {
			b := make([]byte, len(a))
			for i, v := range a {
				if v {
					b[i] = 1
				}
			}
			return string(b)
		}
		start := make([]bool, len(nodes))
		for _, r := range roots {
			start[r] = true
		}
		closure(start)
		sets := [][]bool{start}
		sid := map[string]int{key(start): 0}
		for st := 0; st < len(sets); st++ {
			for v := 0; v < 256; v++ {
				next := make([]bool, len(nodes))
				for i, on := range sets[st] {
					if on {
						for _, n := range nodes[i].edge[byte(v)] {
							next[n] = true
						}
					}
				}
				for _, r := range roots {
					next[r] = true
				}
				closure(next)
				k := key(next)
				n, ok := sid[k]
				if !ok {
					if len(sets) >= maxScopedStates {
						return nil, fmt.Errorf("scope %s/%s matcher exceeds %d states", scope.Type, scope.Name, maxScopedStates)
					}
					n = len(sets)
					sid[k] = n
					sets = append(sets, next)
				}
				tr := runtimeAutomatonTransition{NextState: uint32(n)}
				for i, on := range next {
					if on {
						tr.Matches |= nodes[i].output.Matches
						tr.Rules |= nodes[i].output.Rules
						tr.Flags |= nodes[i].output.Flags
					}
				}
				mapKey := (id*maxScopedStates+uint32(st))*256 + uint32(v)
				out[mapKey] = tr
			}
		}
	}
	return out, nil
}

func applyRules(dir string, patterns, configs, transitions, scoped, scopes *ebpf.Map) error {
	rules, sigs, ruleConfigs, err := loadRules(dir)
	if err != nil {
		return err
	}
	compiled, err := buildAutomatonTransitions(rules)
	if err != nil {
		return err
	}
	scopedCompiled, err := buildScopedTransitions(rules)
	if err != nil {
		return err
	}
	scopeIDs, err := scopeIDMap(rules)
	if err != nil {
		return err
	}
	if len(scopedCompiled) > maxScopes*maxScopedStates*256 {
		return fmt.Errorf("scoped transition count exceeds configured capacity")
	}
	for scope, id := range scopeIDs {
		key := makeRuntimeScopeKey(scope)
		if err := scopes.Update(&key, id, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("loading scope %s/%s: %w", scope.Type, scope.Name, err)
		}
	}
	for key, value := range scopedCompiled {
		if err := scoped.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("loading scoped transition %d: %w", key, err)
		}
	}
	for key, value := range compiled {
		if err := transitions.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("loading automaton transition %d: %w", key, err)
		}
	}
	for i := uint32(0); i < maxRuntimeSignatures; i++ {
		var v runtimeSignature
		if int(i) < len(sigs) {
			v = sigs[i]
		}
		if err := patterns.Update(i, v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("loading signature index %d: %w", i, err)
		}
	}
	for i := uint32(0); i < maxRuntimeRules; i++ {
		var v runtimeRule
		if int(i) < len(ruleConfigs) {
			v = ruleConfigs[i]
		}
		if err := configs.Update(i, v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("loading rule index %d: %w", i, err)
		}
	}
	log.Printf("loaded eBPF rules=%d signatures=%d structured_scopes=%d", len(rules), len(sigs), len(scopeIDs))
	return nil
}

func buildAutomatonTransitions(rules []RuleFile) (map[uint32]runtimeAutomatonTransition, error) {
	transitions := make(map[uint32]runtimeAutomatonTransition)
	for mode := 0; mode < 2; mode++ {
		nodes := []automatonNode{{next: make(map[byte]int)}}
		sigIndex := uint32(0)
		for ruleIndex, rule := range rules {
			ruleEnabled := rule.Enabled != nil && *rule.Enabled
			for _, signature := range rule.Signatures {
				if signature.Matcher != nil {
					sigIndex++
					continue
				}
				caseSensitive := signature.CaseSensitive == nil || *signature.CaseSensitive
				if ruleEnabled && caseSensitive == (mode == 0) {
					state := 0
					for _, char := range []byte(signature.Pattern) {
						if mode == 1 {
							char = asciiLower(char)
						}
						next, ok := nodes[state].next[char]
						if !ok {
							if len(nodes) >= 512 {
								return nil, fmt.Errorf("rule set exceeds 512 states in the signature automaton")
							}
							next = len(nodes)
							nodes[state].next[char] = next
							nodes = append(nodes, automatonNode{next: make(map[byte]int)})
						}
						state = next
					}
					nodes[state].output.Matches |= uint32(1) << sigIndex
					nodes[state].output.Rules |= uint32(1) << uint32(ruleIndex)
					nodes[state].output.Flags |= legacyVerdictMask(rule.Vulnerability, signature.ID, []byte(signature.Pattern))
				}
				sigIndex++
			}
		}

		queue := make([]int, 0, len(nodes))
		for _, child := range nodes[0].next {
			nodes[child].fail = 0
			queue = append(queue, child)
		}
		for head := 0; head < len(queue); head++ {
			state := queue[head]
			for char, child := range nodes[state].next {
				failure := nodes[state].fail
				for failure != 0 {
					if _, ok := nodes[failure].next[char]; ok {
						break
					}
					failure = nodes[failure].fail
				}
				if fallback, ok := nodes[failure].next[char]; ok && fallback != child {
					nodes[child].fail = fallback
				}
				failOutput := nodes[nodes[child].fail].output
				nodes[child].output.Matches |= failOutput.Matches
				nodes[child].output.Rules |= failOutput.Rules
				nodes[child].output.Flags |= failOutput.Flags
				queue = append(queue, child)
			}
		}

		for state := range nodes {
			for value := 0; value < 256; value++ {
				char := byte(value)
				next := state
				for next != 0 {
					if _, ok := nodes[next].next[char]; ok {
						break
					}
					next = nodes[next].fail
				}
				if child, ok := nodes[next].next[char]; ok {
					next = child
				}
				output := nodes[next].output
				if next == 0 && len(nodes[0].next) > 0 {
					if child, ok := nodes[0].next[char]; ok {
						next = child
						output = nodes[next].output
					}
				}
				if next == 0 && output.Matches == 0 {
					continue
				}
				mapState := uint32(state)
				if mode == 1 {
					mapState += 512
				}
				key := mapState*256 + uint32(value)
				output.NextState = uint32(next)
				transitions[key] = output
			}
		}
	}
	return transitions, nil
}
