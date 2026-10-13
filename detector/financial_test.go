package detector

import (
	"testing"
)

// helper to generate a mathematically valid Luhn card number
func makeLuhn(prefix string, totalLen int) string {
	digits := prefix
	for len(digits) < totalLen-1 {
		digits += "0"
	}
	sum := 0
	alt := true
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	check := (10 - (sum % 10)) % 10
	return digits + string(rune('0'+check))
}

func TestFinancialDetectorPaymentCardsPositive(t *testing.T) {
	d := NewFinancialDetector()

	// 10+ positive card test cases across card brands and formats
	tests := []struct {
		name     string
		input    string
		expected string
		category string
	}{
		{
			name:     "Visa 16 digits continuous",
			input:    "Card: " + makeLuhn("4111", 16) + " on file",
			expected: makeLuhn("4111", 16),
			category: "payment_card",
		},
		{
			name:     "Visa 16 digits hyphenated",
			input:    "Number " + makeLuhn("4111", 16)[:4] + "-" + makeLuhn("4111", 16)[4:8] + "-" + makeLuhn("4111", 16)[8:12] + "-" + makeLuhn("4111", 16)[12:] + " used",
			expected: makeLuhn("4111", 16)[:4] + "-" + makeLuhn("4111", 16)[4:8] + "-" + makeLuhn("4111", 16)[8:12] + "-" + makeLuhn("4111", 16)[12:],
			category: "payment_card",
		},
		{
			name:     "Visa 16 digits space separated",
			input:    "Account " + makeLuhn("4111", 16)[:4] + " " + makeLuhn("4111", 16)[4:8] + " " + makeLuhn("4111", 16)[8:12] + " " + makeLuhn("4111", 16)[12:] + " billed",
			expected: makeLuhn("4111", 16)[:4] + " " + makeLuhn("4111", 16)[4:8] + " " + makeLuhn("4111", 16)[8:12] + " " + makeLuhn("4111", 16)[12:],
			category: "payment_card",
		},
		{
			name:     "Visa 13 digits legacy",
			input:    "Old card " + makeLuhn("4000", 13) + " here",
			expected: makeLuhn("4000", 13),
			category: "payment_card",
		},
		{
			name:     "Mastercard 16 digits 51-55 range",
			input:    "Mastercard: " + makeLuhn("5100", 16) + " active",
			expected: makeLuhn("5100", 16),
			category: "payment_card",
		},
		{
			name:     "Mastercard 16 digits 2221-2720 range",
			input:    "Mastercard 2-series: " + makeLuhn("2221", 16) + " ok",
			expected: makeLuhn("2221", 16),
			category: "payment_card",
		},
		{
			name:     "American Express 15 digits 34 prefix",
			input:    "Amex: " + makeLuhn("3400", 15) + " charged",
			expected: makeLuhn("3400", 15),
			category: "payment_card",
		},
		{
			name:     "American Express 15 digits 37 prefix",
			input:    "Amex: " + makeLuhn("3700", 15) + " charged",
			expected: makeLuhn("3700", 15),
			category: "payment_card",
		},
		{
			name:     "Discover 16 digits 6011 prefix",
			input:    "Discover " + makeLuhn("6011", 16) + " ready",
			expected: makeLuhn("6011", 16),
			category: "payment_card",
		},
		{
			name:     "Discover 16 digits 65 prefix",
			input:    "Discover " + makeLuhn("6500", 16) + " processed",
			expected: makeLuhn("6500", 16),
			category: "payment_card",
		},
		{
			name:     "Diners Club 14 digits",
			input:    "Diners: " + makeLuhn("3600", 14) + " approved",
			expected: makeLuhn("3600", 14),
			category: "payment_card",
		},
		{
			name:     "JCB 16 digits",
			input:    "JCB card " + makeLuhn("3528", 16) + " verified",
			expected: makeLuhn("3528", 16),
			category: "payment_card",
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
				t.Errorf("expected Validated=true for Luhn checked card")
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("expected ConfidenceHigh, got %v", f.Confidence)
			}
		})
	}
}

func TestFinancialDetectorIBANPositive(t *testing.T) {
	d := NewFinancialDetector()

	// 10 positive IBAN cases across European and international formats
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Germany IBAN continuous",
			input:    "Transfer to DE89370400440532013000 now",
			expected: "DE89370400440532013000",
		},
		{
			name:     "Germany IBAN with spaces",
			input:    "Wire to DE89 3704 0044 0532 0130 00 please",
			expected: "DE89 3704 0044 0532 0130 00",
		},
		{
			name:     "United Kingdom IBAN",
			input:    "GB IBAN is GB29NWBK60161331926819 confirmed",
			expected: "GB29NWBK60161331926819",
		},
		{
			name:     "France IBAN",
			input:    "French account FR1420041010050500013M02606 for invoice",
			expected: "FR1420041010050500013M02606",
		},
		{
			name:     "Netherlands IBAN",
			input:    "Dutch account NL91ABNA0417164300 paid",
			expected: "NL91ABNA0417164300",
		},
		{
			name:     "Italy IBAN",
			input:    "Italian IBAN: IT60X0542811101000000123456 received",
			expected: "IT60X0542811101000000123456",
		},
		{
			name:     "Spain IBAN",
			input:    "Spanish IBAN ES9121000418450200051332 recorded",
			expected: "ES9121000418450200051332",
		},
		{
			name:     "Switzerland IBAN",
			input:    "Swiss account CH9300762011623852957 registered",
			expected: "CH9300762011623852957",
		},
		{
			name:     "Austria IBAN",
			input:    "Austrian bank AT611904300234573201 valid",
			expected: "AT611904300234573201",
		},
		{
			name:     "Belgium IBAN",
			input:    "Belgian account BE68539007547034 verified",
			expected: "BE68539007547034",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected IBAN finding for input %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expected {
				t.Errorf("expected matched span %q, got %q", tt.expected, matched)
			}
			if f.Category != "iban" {
				t.Errorf("expected category 'iban', got %q", f.Category)
			}
			if f.Tier != TierT3Restricted {
				t.Errorf("expected TierT3Restricted, got %v", f.Tier)
			}
			if !f.Validated {
				t.Errorf("expected Validated=true for mod-97 checked IBAN")
			}
		})
	}
}

func TestFinancialDetectorNegative(t *testing.T) {
	d := NewFinancialDetector()

	negatives := []string{
		"Clean document with no financial information",
		"Card number 4111000000000000 fails Luhn check",
		"Card number 5100000000000000 fails Luhn check",
		"Card number 340000000000000 fails Luhn check",
		"Too short digit string 1234567890",
		"Random 16 digit number 9999000000000000 with invalid issuer prefix",
		"Version string 1.2.3.4.5.6.7.8 should not match",
		"ISO date 2024-01-15 12:30:00",
		"Invalid IBAN DE89370400440532013009 fails mod-97",
		"Invalid IBAN country length DE123456",
		"Placeholder [PAYMENT_CARD_REDACTED]",
		"Placeholder [IBAN_REDACTED]",
		"Hex hash 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
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

func TestFinancialDetectorEdgeCases(t *testing.T) {
	d := NewFinancialDetector()

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// Card at start of text
	card := makeLuhn("4111", 16)
	inputStart := card + " is the primary payment card."
	findings := d.Detect(inputStart)
	if len(findings) != 1 || findings[0].Start != 0 || findings[0].End != 16 {
		t.Fatalf("expected finding at start [0, 16), got: %+v", findings)
	}

	// Card at end of text
	inputEnd := "Primary card: " + card
	findingsEnd := d.Detect(inputEnd)
	expectedStart := len("Primary card: ")
	if len(findingsEnd) != 1 || findingsEnd[0].Start != expectedStart || findingsEnd[0].End != len(inputEnd) {
		t.Fatalf("expected finding at end, got: %+v", findingsEnd)
	}
}

func FuzzFinancialDetector(f *testing.F) {
	f.Add("Card: 4111-0000-0000-0043 on file")
	f.Add("DE89 3704 0044 0532 0130 00")
	f.Add("1234567890123456")
	f.Add("")
	f.Add("[PAYMENT_CARD_REDACTED]")

	d := NewFinancialDetector()
	f.Fuzz(func(t *testing.T, text string) {
		findings := d.Detect(text)
		for _, f := range findings {
			if f.Start < 0 || f.Start >= f.End || f.End > len(text) {
				t.Fatalf("invalid span [%d, %d) for text length %d", f.Start, f.End, len(text))
			}
		}
	})
}
