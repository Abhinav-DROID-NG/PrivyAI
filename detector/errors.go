package detector

import (
	"errors"
	"fmt"
)

// ErrDetectorPanic is returned when a detector panics during execution.
var ErrDetectorPanic = errors.New("privyai: detector panic recovered")

// ErrRegistry indicates an error during detector registration.
var ErrRegistry = errors.New("privyai: registry error")

// ErrInvalidRule is returned when a detection or policy rule is malformed.
var ErrInvalidRule = errors.New("privyai: invalid rule specification")

// DetectorPanicError provides details about a detector panic without exposing raw input.
type DetectorPanicError struct {
	DetectorName string
	Reason       string
}

// Error implements error.
func (e *DetectorPanicError) Error() string {
	return fmt.Sprintf("privyai: detector %q panicked: %s", e.DetectorName, e.Reason)
}

// Unwrap returns ErrDetectorPanic.
func (e *DetectorPanicError) Unwrap() error {
	return ErrDetectorPanic
}

// ErrInvalidSpan is returned when a finding span has invalid offsets or violates rune boundaries.
var ErrInvalidSpan = errors.New("privyai: invalid finding span or rune boundary")

// SpanError provides details about a span boundary or indexing error without exposing sensitive values.
type SpanError struct {
	Start  int
	End    int
	Length int
	Reason string
}

// Error implements error.
func (e *SpanError) Error() string {
	return fmt.Sprintf("privyai: span [%d, %d) invalid for text length %d: %s", e.Start, e.End, e.Length, e.Reason)
}

// Unwrap returns ErrInvalidSpan.
func (e *SpanError) Unwrap() error {
	return ErrInvalidSpan
}
