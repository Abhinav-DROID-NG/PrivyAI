package privyai

import (
	"fmt"
	"regexp"
)

// DefaultMaxInputBytes is 10 MiB.
const DefaultMaxInputBytes = 10 * 1024 * 1024

// ReplacementStrategy defines how redacted values are substituted.
type ReplacementStrategy int

const (
	// ReplacementStrategyLabel replaces findings with category tokens like [EMAIL_REDACTED].
	ReplacementStrategyLabel ReplacementStrategy = 0
	// ReplacementStrategyFixedMask replaces findings with a fixed mask like ****.
	ReplacementStrategyFixedMask ReplacementStrategy = 1
	// ReplacementStrategyPartialMask replaces findings keeping partial characters (e.g. ***1234).
	ReplacementStrategyPartialMask ReplacementStrategy = 2
	// ReplacementStrategyHMAC replaces findings with a deterministic HMAC-SHA256 hex/token.
	ReplacementStrategyHMAC ReplacementStrategy = 3
)

// String returns the name of the replacement strategy.
func (s ReplacementStrategy) String() string {
	switch s {
	case ReplacementStrategyLabel:
		return "LABEL"
	case ReplacementStrategyFixedMask:
		return "FIXED_MASK"
	case ReplacementStrategyPartialMask:
		return "PARTIAL_MASK"
	case ReplacementStrategyHMAC:
		return "HMAC"
	default:
		return fmt.Sprintf("ReplacementStrategy(%d)", int(s))
	}
}

// PartialMaskConfig specifies rules for partial masking.
type PartialMaskConfig struct {
	KeepChars int  `json:"keep_chars"` // Number of characters to retain
	KeepEnd   bool `json:"keep_end"`   // If true, keeps trailing chars; if false, keeps leading chars
	MaskChar  rune `json:"mask_char"`  // Character used for masking (default '*')
}

// ReplacementConfig configures redaction substitution behaviors.
type ReplacementConfig struct {
	DefaultStrategy    ReplacementStrategy            `json:"default_strategy"`
	CategoryStrategies map[string]ReplacementStrategy `json:"category_strategies,omitempty"`
	FixedMaskText      string                         `json:"fixed_mask_text,omitempty"`
	HMACKey            []byte                         `json:"-"` // sensitive key, excluded from JSON serialization
	HMACLength         int                            `json:"hmac_length,omitempty"`
	PartialMasks       map[string]PartialMaskConfig   `json:"partial_masks,omitempty"`
}

// FailClosedBehavior defines redaction output behavior if an unrecoverable error or span corruption occurs.
type FailClosedBehavior int

const (
	// FailClosedNoOutput returns empty string for Sanitized on error.
	FailClosedNoOutput FailClosedBehavior = 0
	// FailClosedRedactAll returns a global redaction marker replacing the entire text on error.
	FailClosedRedactAll FailClosedBehavior = 1
)

// DatabaseRedactMode specifies whether to redact only the credential component or the full URI.
type DatabaseRedactMode int

const (
	// DatabaseRedactPasswordOnly redacts only the user/password portion of connection strings.
	DatabaseRedactPasswordOnly DatabaseRedactMode = 0
	// DatabaseRedactFullURL redacts the entire database connection string.
	DatabaseRedactFullURL DatabaseRedactMode = 1
)

// CustomRule defines a user-specified regular expression detection rule.
type CustomRule struct {
	Name            string     `json:"name"`
	Pattern         string     `json:"pattern"`
	Category        string     `json:"category"`
	Tier            Tier       `json:"tier"`
	Confidence      Confidence `json:"confidence"`
	Validator       string     `json:"validator,omitempty"`
	RequiredContext []string   `json:"required_context,omitempty"`
}

// Config specifies the configuration for the PrivyAI engine.
type Config struct {
	EnabledDetectors        []string
	PolicyJSON              []byte
	PolicyPath              string
	TierOverrides           map[string]Tier
	DefaultTier             Tier
	CustomRules             []CustomRule
	Replacement             ReplacementConfig
	MaxInputBytes           int64
	EntropyDetection        bool
	EntropyThreshold        float64
	IdentifierJurisdictions []string
	DatabaseRedactMode      DatabaseRedactMode
	FailClosedOnError       bool
	FailClosedBehavior      FailClosedBehavior
	AllowInvalidUTF8        bool
}

// DefaultConfig returns a secure default configuration.
func DefaultConfig() Config {
	return Config{
		EnabledDetectors: nil, // nil indicates all built-in detectors enabled
		DefaultTier:      TierT2Confidential,
		Replacement: ReplacementConfig{
			DefaultStrategy: ReplacementStrategyLabel,
			FixedMaskText:   "****",
			HMACLength:      16,
		},
		MaxInputBytes:           DefaultMaxInputBytes,
		EntropyDetection:        false,
		EntropyThreshold:        4.5,
		IdentifierJurisdictions: []string{"US"},
		DatabaseRedactMode:      DatabaseRedactPasswordOnly,
		FailClosedOnError:       true,
		FailClosedBehavior:      FailClosedNoOutput,
		AllowInvalidUTF8:        false,
	}
}

// Validate verifies the configuration integrity, rejecting invalid values.
func (c Config) Validate() error {
	if c.MaxInputBytes < 0 {
		return fmt.Errorf("%w: MaxInputBytes cannot be negative", ErrInvalidConfig)
	}

	if c.DefaultTier < TierT0Public || c.DefaultTier > TierT4Critical {
		return fmt.Errorf("%w: DefaultTier %v is out of range", ErrInvalidConfig, c.DefaultTier)
	}

	// Validate HMAC replacement settings if used
	if c.Replacement.DefaultStrategy == ReplacementStrategyHMAC {
		if len(c.Replacement.HMACKey) == 0 {
			return ErrHMACKeyRequired
		}
	}
	for cat, strat := range c.Replacement.CategoryStrategies {
		if strat == ReplacementStrategyHMAC && len(c.Replacement.HMACKey) == 0 {
			return fmt.Errorf("%w for category %q", ErrHMACKeyRequired, cat)
		}
	}

	// Validate CustomRules
	for idx, cr := range c.CustomRules {
		if cr.Name == "" {
			return &RuleError{RuleIndex: idx, Reason: "custom rule must have a non-empty name"}
		}
		if cr.Pattern == "" {
			return &RuleError{RuleIndex: idx, RuleName: cr.Name, Reason: "custom rule pattern cannot be empty"}
		}
		if _, err := regexp.Compile(cr.Pattern); err != nil {
			return &RuleError{RuleIndex: idx, RuleName: cr.Name, Reason: fmt.Sprintf("invalid regex: %v", err)}
		}
		if cr.Category == "" {
			return &RuleError{RuleIndex: idx, RuleName: cr.Name, Reason: "custom rule must specify a category"}
		}
		if cr.Tier < TierT0Public || cr.Tier > TierT4Critical {
			return &RuleError{RuleIndex: idx, RuleName: cr.Name, Reason: fmt.Sprintf("invalid tier %v", cr.Tier)}
		}
		if cr.Confidence < ConfidenceLow || cr.Confidence > ConfidenceHigh {
			return &RuleError{RuleIndex: idx, RuleName: cr.Name, Reason: fmt.Sprintf("invalid confidence %v", cr.Confidence)}
		}
	}

	return nil
}
