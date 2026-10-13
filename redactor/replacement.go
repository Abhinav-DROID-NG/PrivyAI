package redactor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/YOURUSER/privyai/detector"
)

// ErrHMACKeyRequired is returned when HMAC strategy is used without a key.
var ErrHMACKeyRequired = errors.New("privyai: HMAC key is required for HMAC replacement strategy")

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

// FormatReplacement generates the replacement string for a given finding based on configuration.
func FormatReplacement(raw string, f detector.Finding, cfg ReplacementConfig) string {
	strategy := cfg.DefaultStrategy
	if specific, exists := cfg.CategoryStrategies[f.Category]; exists {
		strategy = specific
	}

	switch strategy {
	case ReplacementStrategyFixedMask:
		if cfg.FixedMaskText != "" {
			return cfg.FixedMaskText
		}
		return "****"

	case ReplacementStrategyPartialMask:
		pCfg, exists := cfg.PartialMasks[f.Category]
		if !exists {
			pCfg = PartialMaskConfig{KeepChars: 4, KeepEnd: true, MaskChar: '*'}
		}
		if pCfg.MaskChar == 0 {
			pCfg.MaskChar = '*'
		}
		runeCount := utf8.RuneCountInString(raw)
		if runeCount <= pCfg.KeepChars {
			// If total length is <= KeepChars, mask all runes to avoid full exposure
			return strings.Repeat(string(pCfg.MaskChar), runeCount)
		}

		runes := []rune(raw)
		maskCount := runeCount - pCfg.KeepChars
		maskStr := strings.Repeat(string(pCfg.MaskChar), maskCount)

		if pCfg.KeepEnd {
			// Keep trailing chars
			return maskStr + string(runes[maskCount:])
		}
		// Keep leading chars
		return string(runes[:pCfg.KeepChars]) + maskStr

	case ReplacementStrategyHMAC:
		if len(cfg.HMACKey) == 0 {
			// Fallback to label if HMAC key missing during formatting
			return formatLabel(f.Category)
		}
		mac := hmac.New(sha256.New, cfg.HMACKey)
		mac.Write([]byte(raw))
		h := hex.EncodeToString(mac.Sum(nil))
		length := cfg.HMACLength
		if length <= 0 || length > len(h) {
			length = 16
		}
		return fmt.Sprintf("[HMAC_%s]", h[:length])

	case ReplacementStrategyLabel:
		fallthrough
	default:
		return formatLabel(f.Category)
	}
}

func formatLabel(category string) string {
	catUpper := strings.ToUpper(category)
	return fmt.Sprintf("[%s_REDACTED]", catUpper)
}
