package detector

import (
	"testing"
)

func TestPhoneDetectorPositive(t *testing.T) {
	positives := []struct {
		input         string
		expectedPhone string
	}{
		{"Call me at +14155552671 now", "+14155552671"},
		{"Support line: +44 20 7946 0958 today", "+44 20 7946 0958"},
		{"Dial +1-800-555-0199 for free help", "+1-800-555-0199"},
		{"Office number is (555) 123-4567.", "(555) 123-4567"},
		{"Direct: 555-123-4567 extension 10", "555-123-4567"},
		{"Contact 555 123 4567 please", "555 123 4567"},
		{"French office: +33 1 42 68 55 55", "+33 1 42 68 55 55"},
		{"German number: +49 30 1234567", "+49 30 1234567"},
		{"Local line (020) 7946 0958 available", "(020) 7946 0958"},
		{"Mobile +81 90 1234 5678 in Japan", "+81 90 1234 5678"},
		{"US phone with country code: +1 (555) 234-5678", "+1 (555) 234-5678"},
		{"Australian number +61 2 9876 5432", "+61 2 9876 5432"},
	}

	d := NewPhoneDetector()

	for _, tt := range positives {
		t.Run(tt.input, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected phone finding in %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expectedPhone {
				t.Errorf("expected matched phone %q, got %q", tt.expectedPhone, matched)
			}
			if f.Category != "phone" {
				t.Errorf("expected category 'phone', got %q", f.Category)
			}
			if f.Tier != TierT1Personal {
				t.Errorf("expected TierT1Personal, got %v", f.Tier)
			}
			if !f.Validated {
				t.Errorf("expected Validated=true")
			}
		})
	}
}

func TestPhoneDetectorNegative(t *testing.T) {
	negatives := []string{
		"Today is 2024-01-15 in the calendar",
		"Released on 2023-12-31 at midnight",
		"Date format 1999-05-20 was used",
		"Version number is 1.2.3.4 for release",
		"Software version 2.15.0 published",
		"Timestamp 2024-01-15T10:30:00 logged",
		"Meeting at 14:30:00 today",
		"Long tracking id 12345678901234567890 should not match",
		"Account ID 9876543210123456 without separator",
		"Too short number 123-45",
		"Placeholder [PHONE_REDACTED]",
		"Path /api/v1/item/123-456/view",
		"Email user123-4567@domain.com should not trigger phone",
		"Identifier ID_123-456-7890_item",
		"Unbalanced parentheses (555-1234567",
	}

	d := NewPhoneDetector()

	for _, input := range negatives {
		t.Run(input, func(t *testing.T) {
			findings := d.Detect(input)
			if len(findings) > 0 {
				t.Fatalf("expected NO findings for %q, got %d findings: %+v", input, len(findings), findings)
			}
		})
	}
}

func TestPhoneDetectorEdgeCases(t *testing.T) {
	d := NewPhoneDetector()

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// Phone at start of string
	inputStart := "+1-800-555-0199 is toll free"
	findingsStart := d.Detect(inputStart)
	if len(findingsStart) != 1 || findingsStart[0].Start != 0 {
		t.Errorf("expected phone at start: %+v", findingsStart)
	}

	// Phone at end of string
	inputEnd := "Call +1-800-555-0199"
	findingsEnd := d.Detect(inputEnd)
	if len(findingsEnd) != 1 || findingsEnd[0].End != len(inputEnd) {
		t.Errorf("expected phone at end: %+v", findingsEnd)
	}

	// Multiple phones
	multiple := "Call +1-800-555-0199 or (555) 234-5678"
	findingsMultiple := d.Detect(multiple)
	if len(findingsMultiple) != 2 {
		t.Fatalf("expected 2 phones, got %d", len(findingsMultiple))
	}
}
