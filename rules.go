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
	maxRuntimeSignatures       = 32
	maxRuntimeRules            = 32
	maxPatternBytes            = 24
	runtimeRuleAny       uint8 = 0
	runtimeRuleAll       uint8 = 1
)

type RuleFile struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	Vulnerability string `yaml:"vulnerability"`
	Description   string `yaml:"description"`
	Enabled       *bool  `yaml:"enabled"`
	Severity      string `yaml:"severity"`
	Match         struct {
		Operator string `yaml:"operator"`
	} `yaml:"match"`
	Signatures []struct {
		ID            string `yaml:"id"`
		Pattern       string `yaml:"pattern"`
		CaseSensitive *bool  `yaml:"case_sensitive"`
	} `yaml:"signatures"`
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
	Operator      uint8
	Pad           uint16
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
		op := strings.ToLower(strings.TrimSpace(rule.Match.Operator))
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
		if op != "any" {
			return nil, nil, nil, fmt.Errorf("%s: match.operator must be any; all is not supported by the kernel matcher", file)
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
		if op == "all" {
			rr.Operator = runtimeRuleAll
		} else {
			rr.Operator = runtimeRuleAny
		}
		localIDs := map[string]bool{}
		for _, item := range rule.Signatures {
			sigID := strings.TrimSpace(item.ID)
			if sigID == "" || localIDs[sigID] {
				return nil, nil, nil, fmt.Errorf("%s: signature id is empty or duplicated: %q", file, sigID)
			}
			localIDs[sigID] = true
			pat := []byte(item.Pattern)
			if len(pat) == 0 || len(pat) > maxPatternBytes {
				return nil, nil, nil, fmt.Errorf("%s: signature %s pattern must be 1..%d bytes", file, sigID, maxPatternBytes)
			}
			for _, b := range pat {
				if b > 0x7f {
					return nil, nil, nil, fmt.Errorf("%s: signature %s pattern must be ASCII", file, sigID)
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

func applyRules(dir string, patterns, configs, transitions *ebpf.Map) error {
	rules, sigs, ruleConfigs, err := loadRules(dir)
	if err != nil {
		return err
	}
	compiled, err := buildAutomatonTransitions(rules)
	if err != nil {
		return err
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
	log.Printf("loaded eBPF rules=%d signatures=%d", len(rules), len(sigs))
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
