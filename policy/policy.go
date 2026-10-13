// Package policy evaluates ordered, configurable enforcement rules.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"

	"github.com/YOURUSER/privyai/detector"
)

func parseTier(data json.RawMessage) (*detector.Tier, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("tier must be a named string")
	}
	tier, err := detector.ParseTier(value)
	if err != nil {
		return nil, err
	}
	return &tier, nil
}

// Rule is an ordered policy rule. Nil tier bounds are unbounded.
type Rule struct {
	ID               string          `json:"id,omitempty"`
	Name             string          `json:"name,omitempty"`
	Category         string          `json:"category,omitempty"`
	MinTier          *detector.Tier  `json:"min_tier,omitempty"`
	MaxTier          *detector.Tier  `json:"max_tier,omitempty"`
	Context          string          `json:"context,omitempty"`
	Action           detector.Action `json:"action"`
	ReplacementLabel string          `json:"replacement_label,omitempty"`
	Conditions       []string        `json:"conditions,omitempty"`
	Priority         *int            `json:"priority,omitempty"`
}

// UnmarshalJSON enforces named tier values in policy documents.
func (r *Rule) UnmarshalJSON(data []byte) error {
	type rawRule struct {
		ID               string          `json:"id,omitempty"`
		Name             string          `json:"name,omitempty"`
		Category         string          `json:"category,omitempty"`
		MinTier          json.RawMessage `json:"min_tier,omitempty"`
		MaxTier          json.RawMessage `json:"max_tier,omitempty"`
		Context          string          `json:"context,omitempty"`
		Action           detector.Action `json:"action"`
		ReplacementLabel string          `json:"replacement_label,omitempty"`
		Conditions       []string        `json:"conditions,omitempty"`
		Priority         *int            `json:"priority,omitempty"`
	}
	var raw rawRule
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	min, err := parseTier(raw.MinTier)
	if err != nil {
		return fmt.Errorf("min_tier: %w", err)
	}
	max, err := parseTier(raw.MaxTier)
	if err != nil {
		return fmt.Errorf("max_tier: %w", err)
	}
	*r = Rule{ID: raw.ID, Name: raw.Name, Category: raw.Category, MinTier: min, MaxTier: max,
		Context: raw.Context, Action: raw.Action, ReplacementLabel: raw.ReplacementLabel,
		Conditions: raw.Conditions, Priority: raw.Priority}
	return nil
}

// Policy is an immutable ordered collection of rules.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Evaluation is the result of evaluating one finding.
type Evaluation struct {
	Action           detector.Action
	ReplacementLabel string
	Conditions       []string
}

// Report contains non-fatal policy validation warnings.
type Report struct {
	Warnings []string
}

// Default returns the built-in fail-safe policy.
func Default() Policy {
	t1 := detector.TierT1Personal
	t2 := detector.TierT2Confidential
	t3 := detector.TierT3Restricted
	t4 := detector.TierT4Critical
	return Policy{Rules: []Rule{
		{ID: "t0-allow", MinTier: ptr(detector.TierT0Public), MaxTier: ptr(detector.TierT0Public), Action: detector.ActionAllow},
		{ID: "t1-external-redact", MinTier: &t1, MaxTier: &t1, Context: "external_transmission", Action: detector.ActionRedact},
		{ID: "t1-default-allow", MinTier: &t1, MaxTier: &t1, Action: detector.ActionAllow},
		{ID: "t2-redact", MinTier: &t2, MaxTier: &t2, Action: detector.ActionRedact},
		{ID: "t3-redact", MinTier: &t3, MaxTier: &t3, Action: detector.ActionRedact},
		{ID: "t4-block", MinTier: &t4, MaxTier: ptr(detector.TierT4Critical), Action: detector.ActionBlock},
	}}
}

func ptr(t detector.Tier) *detector.Tier { return &t }

func (r Rule) label() string {
	if r.ID != "" {
		return r.ID
	}
	if r.Name != "" {
		return r.Name
	}
	return "unnamed"
}

func (r Rule) matches(f detector.Finding, context string) bool {
	if r.Category != "" {
		exact := r.Category == f.Category
		if !exact {
			ok, err := path.Match(r.Category, f.Category)
			if err != nil || !ok {
				return false
			}
		}
	}
	if r.MinTier != nil && f.Tier < *r.MinTier || r.MaxTier != nil && f.Tier > *r.MaxTier {
		return false
	}
	return r.Context == "" || r.Context == context
}

func specificity(r Rule) int {
	switch {
	case r.Category != "" && !hasGlob(r.Category):
		return 4
	case r.Category != "":
		return 3
	case r.MinTier != nil || r.MaxTier != nil:
		return 2
	default:
		return 1
	}
}

func hasGlob(s string) bool {
	for _, r := range s {
		if r == '*' || r == '?' || r == '[' {
			return true
		}
	}
	return false
}

// Evaluate applies precedence rules and returns a decision for a finding.
func (p Policy) Evaluate(f detector.Finding, context string) (result Evaluation, err error) {
	defer func() {
		if recover() != nil {
			result = failClosed(f.Tier)
			err = fmt.Errorf("policy evaluation failed")
		}
	}()
	best := -1
	for i := range p.Rules {
		if !p.Rules[i].matches(f, context) {
			continue
		}
		if best < 0 || better(p.Rules[i], p.Rules[best], i, best) {
			best = i
		}
	}
	if best < 0 {
		return failClosed(f.Tier), nil
	}
	rule := p.Rules[best]
	conditions := uniqueSorted(rule.Conditions)
	return Evaluation{Action: rule.Action, ReplacementLabel: rule.ReplacementLabel, Conditions: conditions}, nil
}

func failClosed(tier detector.Tier) Evaluation {
	if tier >= detector.TierT3Restricted {
		return Evaluation{Action: detector.ActionBlock}
	}
	return Evaluation{Action: detector.ActionRedact}
}

func better(a, b Rule, ai, bi int) bool {
	if (a.Priority != nil) != (b.Priority != nil) {
		return a.Priority != nil
	}
	if a.Priority != nil && *a.Priority != *b.Priority {
		return *a.Priority > *b.Priority
	}
	if specificity(a) != specificity(b) {
		return specificity(a) > specificity(b)
	}
	if a.Action != b.Action {
		return a.Action > b.Action
	}
	return ai < bi
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
