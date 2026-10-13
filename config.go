package privyai

import (
	"fmt"
	"regexp"

	"github.com/YOURUSER/privyai/detector"
	"github.com/YOURUSER/privyai/redactor"
)

// DefaultMaxInputBytes is 10 MiB.
const DefaultMaxInputBytes = 10 * 1024 * 1024

// ReplacementStrategy defines how redacted values are substituted.
type ReplacementStrategy = redactor.ReplacementStrategy

const (
	// ReplacementStrategyLabel replaces findings with category tokens like [EMAIL_REDACTED].
	ReplacementStrategyLabel = redactor.ReplacementStrategyLabel
	// ReplacementStrategyFixedMask replaces findings with a fixed mask like ****.
	ReplacementStrategyFixedMask = redactor.ReplacementStrategyFixedMask
	// ReplacementStrategyPartialMask replaces findings keeping partial characters (e.g. ***1234).
	ReplacementStrategyPartialMask = redactor.ReplacementStrategyPartialMask
	// ReplacementStrategyHMAC replaces findings with a deterministic HMAC-SHA256 hex/token.
	ReplacementStrategyHMAC = redactor.ReplacementStrategyHMAC
)

// PartialMaskConfig specifies rules for partial masking.
type PartialMaskConfig = redactor.PartialMaskConfig

// ReplacementConfig configures redaction substitution behaviors.
type ReplacementConfig = redactor.ReplacementConfig

// FailClosedBehavior defines redaction output behavior if an unrecoverable error or span corruption occurs.
type FailClosedBehavior = redactor.FailClosedBehavior

const (
	// FailClosedNoOutput returns empty string for Sanitized on error.
	FailClosedNoOutput = redactor.FailClosedNoOutput
	// FailClosedRedactAll returns a global redaction marker replacing the entire text on error.
	FailClosedRedactAll = redactor.FailClosedRedactAll
)

// DatabaseRedactMode specifies whether to redact only the credential component or the full URI.
type DatabaseRedactMode = detector.DatabaseRedactMode

const (
	// DatabaseRedactPasswordOnly redacts only the user/password portion of connection strings.
	DatabaseRedactPasswordOnly = detector.DatabaseRedactPasswordOnly
	// DatabaseRedactFullURL redacts the entire database connection string.
	DatabaseRedactFullURL = detector.DatabaseRedactFullURL
)

// CustomRule defines a user-specified regular expression detection rule.
type CustomRule = detector.CustomRule

// Config specifies the configuration for the PrivyAI engine.
type Config struct {
	EnabledDetectors []string
	PolicyJSON       []byte
	// PolicyPath is reserved for callers that load policy bytes themselves.
	// The core never reads files; use PolicyJSON to configure an engine.
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
	StructuredMaxDepth      int
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
		StructuredMaxDepth:      100,
	}
}

// Validate verifies the configuration integrity, rejecting invalid values.
func (c Config) Validate() error {
	if c.MaxInputBytes < 0 {
		return fmt.Errorf("%w: MaxInputBytes cannot be negative", ErrInvalidConfig)
	}
	if c.StructuredMaxDepth < 0 {
		return fmt.Errorf("%w: StructuredMaxDepth cannot be negative", ErrInvalidConfig)
	}

	if c.DefaultTier < TierT0Public || c.DefaultTier > TierT4Critical {
		return fmt.Errorf("%w: DefaultTier %v is out of range", ErrInvalidConfig, c.DefaultTier)
	}
	if c.PolicyPath != "" {
		return fmt.Errorf("%w: PolicyPath is unsupported; use PolicyJSON", ErrInvalidConfig)
	}
	for category, tier := range c.TierOverrides {
		if category == "" {
			return fmt.Errorf("%w: TierOverrides contains an empty category", ErrInvalidConfig)
		}
		if !tier.IsValid() {
			return fmt.Errorf("%w: TierOverrides[%q] is invalid", ErrInvalidConfig, category)
		}
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
