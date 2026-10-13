package redactor

import (
	"errors"
	"testing"

	"github.com/YOURUSER/privyai/detector"
)

func TestRedactorRedactBasic(t *testing.T) {
	cfg := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyLabel,
	}
	r := NewRedactor(cfg, FailClosedNoOutput)

	text := "Contact alice@example.com for help and bob@domain.org for sales."
	findings := []detector.Finding{
		{Category: "email", Start: 8, End: 25, Action: detector.ActionRedact},
		{Category: "email", Start: 39, End: 53, Action: detector.ActionRedact},
	}

	sanitized, err := r.Redact(text, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "Contact [EMAIL_REDACTED] for help and [EMAIL_REDACTED] for sales."
	if sanitized != expected {
		t.Errorf("expected %q, got %q", expected, sanitized)
	}
}

func TestRedactorActionFiltering(t *testing.T) {
	cfg := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyLabel,
	}
	r := NewRedactor(cfg, FailClosedNoOutput)

	text := "Contact alice@example.com and keep bob@domain.org visible."
	findings := []detector.Finding{
		{Category: "email", Start: 8, End: 25, Action: detector.ActionRedact},
		{Category: "email", Start: 35, End: 49, Action: detector.ActionAllow}, // should NOT be redacted
	}

	sanitized, err := r.Redact(text, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "Contact [EMAIL_REDACTED] and keep bob@domain.org visible."
	if sanitized != expected {
		t.Errorf("expected %q, got %q", expected, sanitized)
	}
}

func TestRedactorFailClosed(t *testing.T) {
	text := "Hello world"
	invalidFindings := []detector.Finding{
		{Category: "test", Start: 8, End: 4, Action: detector.ActionRedact}, // start > end
	}

	// FailClosedNoOutput
	rNoOutput := NewRedactor(ReplacementConfig{}, FailClosedNoOutput)
	out, err := rNoOutput.Redact(text, invalidFindings)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan, got: %v", err)
	}
	if out != "" {
		t.Errorf("expected empty string for FailClosedNoOutput, got: %q", out)
	}

	// FailClosedRedactAll
	rRedactAll := NewRedactor(ReplacementConfig{}, FailClosedRedactAll)
	outAll, err := rRedactAll.Redact(text, invalidFindings)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan, got: %v", err)
	}
	if outAll != "[REDACTED]" {
		t.Errorf("expected '[REDACTED]' for FailClosedRedactAll, got: %q", outAll)
	}
}

func TestRedactorNoFindings(t *testing.T) {
	r := NewRedactor(ReplacementConfig{}, FailClosedNoOutput)
	text := "Some clean text"
	out, err := r.Redact(text, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != text {
		t.Errorf("expected unchanged text, got %q", out)
	}
}
