package privyai

import (
	"errors"
	"strings"
	"testing"
)

func TestDetectorPanicError(t *testing.T) {
	dpErr := &DetectorPanicError{
		DetectorName: "secrets",
		Reason:       "index out of range",
	}

	if !errors.Is(dpErr, ErrDetectorPanic) {
		t.Errorf("expected errors.Is(dpErr, ErrDetectorPanic) to be true")
	}

	msg := dpErr.Error()
	if !strings.Contains(msg, "secrets") || !strings.Contains(msg, "index out of range") {
		t.Errorf("unexpected error message: %s", msg)
	}
}

func TestSpanError(t *testing.T) {
	sErr := &SpanError{
		Start:  10,
		End:    5,
		Length: 20,
		Reason: "start must be less than end",
	}

	if !errors.Is(sErr, ErrInvalidSpan) {
		t.Errorf("expected errors.Is(sErr, ErrInvalidSpan) to be true")
	}

	msg := sErr.Error()
	if !strings.Contains(msg, "[10, 5)") || !strings.Contains(msg, "start must be less than end") {
		t.Errorf("unexpected error message: %s", msg)
	}
}

func TestRuleError(t *testing.T) {
	rErr := &RuleError{
		RuleIndex: 2,
		RuleName:  "my_custom_rule",
		Reason:    "empty pattern",
	}

	if !errors.Is(rErr, ErrInvalidRule) {
		t.Errorf("expected errors.Is(rErr, ErrInvalidRule) to be true")
	}

	msg := rErr.Error()
	if !strings.Contains(msg, "my_custom_rule") || !strings.Contains(msg, "index 2") {
		t.Errorf("unexpected error message: %s", msg)
	}

	// Without name
	rErrNoName := &RuleError{
		RuleIndex: 0,
		Reason:    "invalid tier",
	}
	msgNoName := rErrNoName.Error()
	if !strings.Contains(msgNoName, "rule at index 0") {
		t.Errorf("unexpected error message: %s", msgNoName)
	}
}
