package privyai

import (
	"errors"
	"fmt"

	"github.com/YOURUSER/privyai/detector"
)

// Sentinel errors for PrivyAI.
var (
	// ErrInputTooLarge is returned when the input text exceeds MaxInputBytes.
	ErrInputTooLarge = errors.New("privyai: input exceeds maximum configured size")

	// ErrInvalidUTF8 is returned when the input string contains invalid UTF-8 byte sequences.
	ErrInvalidUTF8 = errors.New("privyai: input contains invalid UTF-8 byte sequences")

	// ErrInvalidRule is returned when a detection or policy rule is malformed.
	ErrInvalidRule = detector.ErrInvalidRule

	// ErrInvalidSpan is returned when a finding span has invalid offsets or violates rune boundaries.
	ErrInvalidSpan = detector.ErrInvalidSpan

	// ErrPolicyConflict is returned when unresolvable contradictory policy rules exist.
	ErrPolicyConflict = errors.New("privyai: unresolvable policy conflict")

	// ErrDetectorPanic is returned when a detector panics during execution.
	ErrDetectorPanic = detector.ErrDetectorPanic

	// ErrInvalidConfig is returned when engine configuration validation fails.
	ErrInvalidConfig = errors.New("privyai: invalid engine configuration")

	// ErrHMACKeyRequired is returned when HMAC replacement strategy is selected without a key.
	ErrHMACKeyRequired = errors.New("privyai: HMAC key is required for HMAC replacement strategy")
)

// DetectorPanicError provides details about a detector panic without exposing raw input.
type DetectorPanicError = detector.DetectorPanicError

// SpanError provides details about a span boundary or indexing error without exposing sensitive values.
type SpanError = detector.SpanError

// RuleError provides details about a rule specification error without exposing sensitive pattern data.
type RuleError struct {
	RuleIndex int
	RuleName  string
	Reason    string
}

// Error implements error.
func (e *RuleError) Error() string {
	if e.RuleName != "" {
		return fmt.Sprintf("privyai: rule %q (index %d) invalid: %s", e.RuleName, e.RuleIndex, e.Reason)
	}
	return fmt.Sprintf("privyai: rule at index %d invalid: %s", e.RuleIndex, e.Reason)
}

// Unwrap returns ErrInvalidRule.
func (e *RuleError) Unwrap() error {
	return ErrInvalidRule
}
