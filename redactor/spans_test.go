package redactor

import (
	"errors"
	"testing"

	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
)

func TestValidateSpansSuccess(t *testing.T) {
	text := "Hello world, this is a test string for spans."
	findings := []detector.Finding{
		{Start: 0, End: 5},
		{Start: 6, End: 11},
		{Start: 23, End: 27},
		{Start: 39, End: 45}, // ends exactly at len(text)
	}

	if err := ValidateSpans(text, findings); err != nil {
		t.Fatalf("expected valid spans, got error: %v", err)
	}

	// Empty findings
	if err := ValidateSpans(text, nil); err != nil {
		t.Fatalf("expected nil error for empty findings, got: %v", err)
	}
}

func TestValidateSpansNegativeStart(t *testing.T) {
	text := "Hello world"
	findings := []detector.Finding{
		{Start: -1, End: 5},
	}

	err := ValidateSpans(text, findings)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for negative start, got: %v", err)
	}
}

func TestValidateSpansStartGreaterOrEqualEnd(t *testing.T) {
	text := "Hello world"
	findings := []detector.Finding{
		{Start: 5, End: 5},
	}
	if err := ValidateSpans(text, findings); err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for start == end, got: %v", err)
	}

	findingsInverted := []detector.Finding{
		{Start: 8, End: 5},
	}
	if err := ValidateSpans(text, findingsInverted); err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for start > end, got: %v", err)
	}
}

func TestValidateSpansEndExceedsLength(t *testing.T) {
	text := "Hello"
	findings := []detector.Finding{
		{Start: 0, End: 10},
	}
	if err := ValidateSpans(text, findings); err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan when end > len(text), got: %v", err)
	}
}

func TestValidateSpansRuneBoundaryViolation(t *testing.T) {
	// "👋" is a 4-byte UTF-8 sequence: [0xF0, 0x9F, 0x91, 0x8B]
	text := "👋 Hello"

	// Start inside the multi-byte rune
	findingsBadStart := []detector.Finding{
		{Start: 1, End: 5},
	}
	err := ValidateSpans(text, findingsBadStart)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for start on non-rune boundary, got: %v", err)
	}

	// End inside the multi-byte rune
	findingsBadEnd := []detector.Finding{
		{Start: 0, End: 2},
	}
	err = ValidateSpans(text, findingsBadEnd)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for end on non-rune boundary, got: %v", err)
	}
}

func TestValidateSpansOverlappingAndUnsorted(t *testing.T) {
	text := "0123456789ABCDEF"

	// Overlapping spans
	overlapping := []detector.Finding{
		{Start: 2, End: 6},
		{Start: 5, End: 10}, // overlaps with [2, 6)
	}
	err := ValidateSpans(text, overlapping)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for overlapping spans, got: %v", err)
	}

	// Unsorted spans
	unsorted := []detector.Finding{
		{Start: 8, End: 12},
		{Start: 2, End: 5},
	}
	err = ValidateSpans(text, unsorted)
	if err == nil || !errors.Is(err, detector.ErrInvalidSpan) {
		t.Fatalf("expected ErrInvalidSpan for unsorted spans, got: %v", err)
	}
}
