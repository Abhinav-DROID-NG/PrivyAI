package detector

import (
	"testing"
)

func TestIdentifiersDetectorPositive(t *testing.T) {
	d := NewIdentifiersDetector([]string{"US", "UK"})

	tests := []struct {
		name     string
		input    string
		expected string
		category string
	}{
		{
			name:     "Formatted US SSN hyphenated",
			input:    "Employee SSN: 123-45-6789 active",
			expected: "123-45-6789",
			category: "ssn",
		},
		{
			name:     "Formatted US SSN space separated",
			input:    "Record has SSN 219 09 9999 registered",
			expected: "219 09 9999",
			category: "ssn",
		},
		{
			name:     "Formatted US SSN low area",
			input:    "SSN 078-05-1120 found",
			expected: "078-05-1120",
			category: "ssn",
		},
		{
			name:     "Formatted US SSN mid area",
			input:    "Taxpayer 456-78-1234 verified",
			expected: "456-78-1234",
			category: "ssn",
		},
		{
			name:     "Formatted US SSN high valid area",
			input:    "Form 899-12-3456 processed",
			expected: "899-12-3456",
			category: "ssn",
		},
		{
			name:     "Unformatted US SSN with ssn context",
			input:    "Client ssn: 123456789 saved",
			expected: "123456789",
			category: "ssn",
		},
		{
			name:     "Unformatted US SSN with social security context",
			input:    "Their social security number is 219099999 for filing",
			expected: "219099999",
			category: "ssn",
		},
		{
			name:     "Unformatted US SSN with tax id context",
			input:    "Check tax id 456781234 on tax return",
			expected: "456781234",
			category: "ssn",
		},
		{
			name:     "UK NINO continuous suffix A",
			input:    "UK NINO AB123456A is assigned",
			expected: "AB123456A",
			category: "uk_nino",
		},
		{
			name:     "UK NINO with spaces suffix B",
			input:    "National insurance NY 12 34 56 B on record",
			expected: "NY 12 34 56 B",
			category: "uk_nino",
		},
		{
			name:     "UK NINO valid prefix JH suffix C",
			input:    "Worker NINO JH001234C registered",
			expected: "JH001234C",
			category: "uk_nino",
		},
		{
			name:     "UK NINO valid prefix RN suffix D",
			input:    "Policy holder RN987654D valid",
			expected: "RN987654D",
			category: "uk_nino",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected finding for input %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expected {
				t.Errorf("expected matched span %q, got %q", tt.expected, matched)
			}
			if f.Category != tt.category {
				t.Errorf("expected category %q, got %q", tt.category, f.Category)
			}
			if f.Tier != TierT3Restricted {
				t.Errorf("expected TierT3Restricted, got %v", f.Tier)
			}
			if !f.Validated {
				t.Errorf("expected Validated=true")
			}
		})
	}
}

func TestIdentifiersDetectorNegative(t *testing.T) {
	d := NewIdentifiersDetector([]string{"US", "UK"})

	negatives := []string{
		"Clean document with no government ids",
		"Invalid SSN area 000: 000-45-6789",
		"Invalid SSN area 666: 666-45-6789",
		"Invalid SSN area 900+: 900-45-6789",
		"Invalid SSN area 999: 999-45-6789",
		"Invalid SSN group 00: 123-00-6789",
		"Invalid SSN serial 0000: 123-45-0000",
		"Order number 123456789 shipped via standard courier",
		"Part number 219099999 in invoice catalog",
		"Invalid UK NINO disallowed prefix BG: BG123456A",
		"Invalid UK NINO disallowed prefix GB: GB123456A",
		"Invalid UK NINO disallowed first char D: DA123456A",
		"Invalid UK NINO disallowed second char O: AO123456A",
		"Invalid UK NINO suffix E: AB123456E",
		"Placeholder [SSN_REDACTED]",
		"Placeholder [UK_NINO_REDACTED]",
	}

	for _, input := range negatives {
		t.Run(input, func(t *testing.T) {
			findings := d.Detect(input)
			if len(findings) > 0 {
				t.Fatalf("expected NO findings for negative input %q, got: %+v", input, findings)
			}
		})
	}
}

func TestIdentifiersDetectorJurisdictionOptIn(t *testing.T) {
	// Only US enabled
	dUS := NewIdentifiersDetector([]string{"US"})
	ukInput := "Worker NINO AB123456A registered"
	if len(dUS.Detect(ukInput)) != 0 {
		t.Errorf("UK NINO should not be detected when only US jurisdiction is enabled")
	}

	// UK enabled
	dUK := NewIdentifiersDetector([]string{"UK"})
	if len(dUK.Detect(ukInput)) != 1 {
		t.Errorf("UK NINO should be detected when UK jurisdiction is enabled")
	}
}

func TestIdentifiersDetectorEdgeCases(t *testing.T) {
	d := NewIdentifiersDetector([]string{"US", "UK"})

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// SSN at start of string
	inputStart := "123-45-6789 is my SSN"
	findingsStart := d.Detect(inputStart)
	if len(findingsStart) != 1 || findingsStart[0].Start != 0 || findingsStart[0].End != 11 {
		t.Fatalf("expected finding at start [0, 11), got: %+v", findingsStart)
	}

	// SSN at end of string
	inputEnd := "SSN is 123-45-6789"
	findingsEnd := d.Detect(inputEnd)
	if len(findingsEnd) != 1 || findingsEnd[0].Start != len("SSN is ") || findingsEnd[0].End != len(inputEnd) {
		t.Fatalf("expected finding at end, got: %+v", findingsEnd)
	}
}

func FuzzIdentifiersDetector(f *testing.F) {
	f.Add("SSN: 123-45-6789")
	f.Add("QQ123456A")
	f.Add("123456789")
	f.Add("[SSN_REDACTED]")
	f.Add("")

	d := NewIdentifiersDetector([]string{"US", "UK"})
	f.Fuzz(func(t *testing.T, text string) {
		findings := d.Detect(text)
		for _, f := range findings {
			if f.Start < 0 || f.Start >= f.End || f.End > len(text) {
				t.Fatalf("invalid span [%d, %d) for text length %d", f.Start, f.End, len(text))
			}
		}
	})
}
