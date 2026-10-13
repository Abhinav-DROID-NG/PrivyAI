package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
)

// ErrInvalidRule identifies malformed policy rules.
var ErrInvalidRule = errors.New("privyai: invalid policy rule")

func invalid(index int, field string) error {
	return fmt.Errorf("%w: rule index %d field %s", ErrInvalidRule, index, field)
}

// Load parses and strictly validates one JSON policy document.
func Load(data []byte) (Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("%w: invalid policy JSON: %w", ErrInvalidRule, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Policy{}, fmt.Errorf("%w: invalid policy JSON: trailing data", ErrInvalidRule)
		}
		return Policy{}, fmt.Errorf("%w: invalid policy JSON: trailing data", ErrInvalidRule)
	}
	if err := validate(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func validate(p Policy) error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: rules must not be empty", ErrInvalidRule)
	}
	for i, r := range p.Rules {
		if r.Category == "" && r.MinTier == nil && r.MaxTier == nil && r.Context == "" {
			return invalid(i, "rule")
		}
		if r.Action < detector.ActionAllow || r.Action > detector.ActionBlock {
			return invalid(i, "action")
		}
		if r.MinTier != nil && !r.MinTier.IsValid() {
			return invalid(i, "min_tier")
		}
		if r.MaxTier != nil && !r.MaxTier.IsValid() {
			return invalid(i, "max_tier")
		}
		if r.MinTier != nil && r.MaxTier != nil && *r.MinTier > *r.MaxTier {
			return invalid(i, "tier range")
		}
		if r.Category != "" {
			if _, err := path.Match(r.Category, "example"); err != nil {
				return invalid(i, "category")
			}
		}
	}
	return nil
}

// Validate returns non-fatal policy warnings.
func (p Policy) Validate() Report {
	var report Report
	for i, r := range p.Rules {
		for j := i + 1; j < len(p.Rules); j++ {
			other := p.Rules[j]
			if samePrecedence(r, other) && r.Action != other.Action {
				report.Warnings = append(report.Warnings, fmt.Sprintf("rules %d and %d have equal precedence; protective action wins", i, j))
			}
		}
		if r.Action == detector.ActionAllow && (r.MinTier != nil && *r.MinTier >= detector.TierT3Restricted || r.MaxTier != nil && *r.MaxTier >= detector.TierT3Restricted) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("rule %d allows T3/T4 content", i))
		}
	}
	return report
}

func samePrecedence(a, b Rule) bool {
	if (a.Priority == nil) != (b.Priority == nil) {
		return false
	}
	if a.Priority != nil && *a.Priority != *b.Priority {
		return false
	}
	return specificity(a) == specificity(b)
}
