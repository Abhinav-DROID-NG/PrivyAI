package detector

import (
	"errors"
	"fmt"
)

// ErrDetectorPanic is returned when a detector panics during execution.
var ErrDetectorPanic = errors.New("privyai: detector panic recovered")

// ErrRegistry indicates an error during detector registration.
var ErrRegistry = errors.New("privyai: registry error")

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
