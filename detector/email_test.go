package detector

import (
	"strings"
	"testing"
)

func TestEmailDetectorPositive(t *testing.T) {
	positives := []struct {
		input         string
		expectedEmail string
	}{
		{"contact user@example.com for info", "user@example.com"},
		{"alice.smith+tag@work-domain.co.uk is active", "alice.smith+tag@work-domain.co.uk"},
		{"Write to <support@service.io> today", "support@service.io"},
		{"CEO email is \"chief@corp.org\"", "chief@corp.org"},
		{"Single quotes 'dev@internal.net' test", "dev@internal.net"},
		{"Send to alice@example.com.", "alice@example.com"},
		{"Trailing comma bob@sub.domain.com, next", "bob@sub.domain.com"},
		{"Parentheses (help@desk.org) enclosed", "help@desk.org"},
		{"first.last_123@domain.com", "first.last_123@domain.com"},
		{"custom_email-address%test@mail.org", "custom_email-address%test@mail.org"},
		{"admin@123domain.com is valid numeric domain", "admin@123domain.com"},
		{"user@mail-server.domain.com", "user@mail-server.domain.com"},
	}

	d := NewEmailDetector()

	for _, tt := range positives {
		t.Run(tt.input, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected finding for input %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expectedEmail {
				t.Errorf("expected matched email %q, got %q", tt.expectedEmail, matched)
			}
			if f.Category != "email" {
				t.Errorf("expected category 'email', got %q", f.Category)
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

func TestEmailDetectorNegative(t *testing.T) {
	negatives := []string{
		"plain text without any emails",
		"missing domain part user@",
		"missing user part @example.com",
		"double at symbol user@@example.com",
		"no tld user@localhost",
		"invalid tld user@domain.c",
		"invalid tld numeric user@domain.12",
		"leading dot in local .user@domain.com",
		"trailing dot in local user.@domain.com",
		"consecutive dots in local user..name@domain.com",
		"consecutive dots in domain user@domain..com",
		"domain label leading hyphen user@-domain.com",
		"domain label trailing hyphen user@domain-.com",
		"already redacted placeholder [EMAIL_REDACTED]",
		"already redacted placeholder [SECRET_REDACTED]",
		"too long local part " + strings.Repeat("a", 65) + "@example.com",
	}

	d := NewEmailDetector()

	for _, input := range negatives {
		t.Run(input, func(t *testing.T) {
			findings := d.Detect(input)
			if len(findings) > 0 {
				t.Fatalf("expected NO findings for negative input %q, got %d findings: %+v", input, len(findings), findings)
			}
		})
	}
}

func TestEmailDetectorEdgeCases(t *testing.T) {
	d := NewEmailDetector()

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// Email at exact boundary (start of string)
	inputStart := "alice@example.com is here"
	findingsStart := d.Detect(inputStart)
	if len(findingsStart) != 1 || findingsStart[0].Start != 0 || findingsStart[0].End != 17 {
		t.Errorf("expected finding at [0, 17), got: %+v", findingsStart)
	}

	// Email at exact boundary (end of string)
	inputEnd := "Reach out to bob@example.com"
	findingsEnd := d.Detect(inputEnd)
	if len(findingsEnd) != 1 || findingsEnd[0].End != len(inputEnd) {
		t.Errorf("expected finding ending at %d, got: %+v", len(inputEnd), findingsEnd)
	}

	// Multiple emails in text
	multiple := "Write to alice@example.com or bob@example.org for support."
	multipleFindings := d.Detect(multiple)
	if len(multipleFindings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(multipleFindings))
	}
	if multiple[multipleFindings[0].Start:multipleFindings[0].End] != "alice@example.com" {
		t.Errorf("first email mismatch: %s", multiple[multipleFindings[0].Start:multipleFindings[0].End])
	}
	if multiple[multipleFindings[1].Start:multipleFindings[1].End] != "bob@example.org" {
		t.Errorf("second email mismatch: %s", multiple[multipleFindings[1].Start:multipleFindings[1].End])
	}
}
