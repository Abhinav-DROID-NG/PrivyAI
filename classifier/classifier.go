// Package classifier assigns sensitivity tiers to detector findings.
package classifier

import (
	"fmt"
	"sort"

	"github.com/YOURUSER/privyai/detector"
)

var defaultMapping = map[string]detector.Tier{
	"email":                detector.TierT1Personal,
	"phone":                detector.TierT1Personal,
	"ip":                   detector.TierT1Personal,
	"internal_ip":          detector.TierT2Confidential,
	"ssn":                  detector.TierT3Restricted,
	"uk_nino":              detector.TierT3Restricted,
	"payment_card":         detector.TierT3Restricted,
	"iban":                 detector.TierT3Restricted,
	"aws_access_key":       detector.TierT3Restricted,
	"github_token":         detector.TierT3Restricted,
	"slack_token":          detector.TierT3Restricted,
	"stripe_key":           detector.TierT3Restricted,
	"google_api_key":       detector.TierT3Restricted,
	"jwt":                  detector.TierT3Restricted,
	"secret":               detector.TierT3Restricted,
	"private_key":          detector.TierT4Critical,
	"database_credentials": detector.TierT4Critical,
}

// DefaultTierForCategory returns the configured built-in tier requirement and
// whether the category has an explicit built-in mapping.
func DefaultTierForCategory(category string) (detector.Tier, bool) {
	tier, ok := defaultMapping[category]
	return tier, ok
}

// Classifier is immutable and safe for concurrent use.
type Classifier struct {
	mapping     map[string]detector.Tier
	defaultTier detector.Tier
	overrides   map[string]detector.Tier
}

// New validates and constructs a classifier.
func New(defaultTier detector.Tier, overrides map[string]detector.Tier) (*Classifier, error) {
	if !defaultTier.IsValid() {
		return nil, fmt.Errorf("invalid default tier %s", defaultTier)
	}
	mapping := make(map[string]detector.Tier, len(defaultMapping))
	for category, tier := range defaultMapping {
		mapping[category] = tier
	}
	checked := make(map[string]detector.Tier, len(overrides))
	keys := make([]string, 0, len(overrides))
	for category, tier := range overrides {
		if category == "" {
			return nil, fmt.Errorf("invalid tier override key %q", category)
		}
		if !tier.IsValid() {
			return nil, fmt.Errorf("invalid tier override for category %q", category)
		}
		keys = append(keys, category)
		checked[category] = tier
	}
	sort.Strings(keys)
	return &Classifier{mapping: mapping, defaultTier: defaultTier, overrides: checked}, nil
}

// Classify returns a copy of finding with its effective tier.
func (c *Classifier) Classify(f detector.Finding) detector.Finding {
	if tier, ok := c.overrides[f.Category]; ok {
		f.Tier = tier
		return f
	}
	required, ok := c.mapping[f.Category]
	if !ok {
		required = c.defaultTier
	}
	if f.Tier < required {
		f.Tier = required
	}
	return f
}

// ClassifyAll classifies findings without modifying the input slice.
func (c *Classifier) ClassifyAll(findings []detector.Finding) []detector.Finding {
	out := make([]detector.Finding, len(findings))
	for i, finding := range findings {
		out[i] = c.Classify(finding)
	}
	return out
}
