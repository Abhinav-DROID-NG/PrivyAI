package detector

import (
	"testing"
)

func TestCustomDetectorPositive(t *testing.T) {
	rules := []CustomRule{
		{
			Name:       "employee_id",
			Pattern:    `\bEMP-\d{5}\b`,
			Category:   "employee_id",
			Tier:       TierT2Confidential,
			Confidence: ConfidenceHigh,
		},
		{
			Name:            "pin_code",
			Pattern:         `\b\d{6}\b`,
			Category:        "postal_code",
			Tier:            TierT1Personal,
			Confidence:      ConfidenceMedium,
			RequiredContext: []string{"pincode", "postal code"},
		},
		{
			Name:       "custom_card",
			Pattern:    `\b9\d{15}\b`,
			Category:   "custom_card",
			Tier:       TierT3Restricted,
			Confidence: ConfidenceHigh,
			Validator:  "luhn",
		},
	}

	d, err := NewCustomDetector(rules)
	if err != nil {
		t.Fatalf("failed to create custom detector: %v", err)
	}

	// 1. Employee ID match
	inputEmp := "Welcome employee EMP-12345 to the company"
	findingsEmp := d.Detect(inputEmp)
	if len(findingsEmp) != 1 {
		t.Fatalf("expected 1 finding for employee ID, got %d", len(findingsEmp))
	}
	if inputEmp[findingsEmp[0].Start:findingsEmp[0].End] != "EMP-12345" {
		t.Errorf("expected EMP-12345, got %s", inputEmp[findingsEmp[0].Start:findingsEmp[0].End])
	}
	if findingsEmp[0].Category != "employee_id" || findingsEmp[0].Tier != TierT2Confidential {
		t.Errorf("unexpected category/tier: %+v", findingsEmp[0])
	}

	// 2. PIN code with required context
	inputPin := "Delivery pincode: 560001 for shipping"
	findingsPin := d.Detect(inputPin)
	if len(findingsPin) != 1 {
		t.Fatalf("expected 1 finding for pincode with context, got %d", len(findingsPin))
	}
	if inputPin[findingsPin[0].Start:findingsPin[0].End] != "560001" {
		t.Errorf("expected 560001, got %s", inputPin[findingsPin[0].Start:findingsPin[0].End])
	}

	// 3. Custom card passing Luhn
	validLuhn9 := makeLuhn("9000", 16)
	inputCard := "Card number " + validLuhn9 + " registered"
	findingsCard := d.Detect(inputCard)
	if len(findingsCard) != 1 {
		t.Fatalf("expected 1 finding for custom card passing Luhn, got %d", len(findingsCard))
	}
	if !findingsCard[0].Validated {
		t.Errorf("expected Validated=true for luhn validated custom card")
	}
}

func TestCustomDetectorNegative(t *testing.T) {
	rules := []CustomRule{
		{
			Name:            "pin_code",
			Pattern:         `\b\d{6}\b`,
			Category:        "postal_code",
			Tier:            TierT1Personal,
			Confidence:      ConfidenceMedium,
			RequiredContext: []string{"pincode", "postal code"},
		},
		{
			Name:       "custom_card",
			Pattern:    `\b9\d{15}\b`,
			Category:   "custom_card",
			Tier:       TierT3Restricted,
			Confidence: ConfidenceHigh,
			Validator:  "luhn",
		},
	}

	d, err := NewCustomDetector(rules)
	if err != nil {
		t.Fatalf("failed to create custom detector: %v", err)
	}

	negatives := []string{
		"Random 6 digits without required context: 560001 here",
		"Order number 123456 delivered",
		"Card 9000000000000000 fails Luhn check",
		"Placeholder [EMPLOYEE_ID_REDACTED]",
		"Clean document with no matches",
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

func TestCustomDetectorCompilationErrors(t *testing.T) {
	// Invalid regex pattern
	_, err := NewCustomDetector([]CustomRule{
		{Name: "bad_regex", Pattern: "[a-z("},
	})
	if err == nil {
		t.Fatal("expected compilation error for invalid regex, got nil")
	}

	// Empty rule name
	_, err = NewCustomDetector([]CustomRule{
		{Name: "", Pattern: "[a-z]+"},
	})
	if err == nil {
		t.Fatal("expected error for empty rule name, got nil")
	}

	// Empty pattern
	_, err = NewCustomDetector([]CustomRule{
		{Name: "empty_pattern", Pattern: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty pattern, got nil")
	}
}

func TestCustomDetectorEdgeCases(t *testing.T) {
	d, err := NewCustomDetector(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil rules: %v", err)
	}
	if len(d.Detect("some text")) != 0 {
		t.Error("expected 0 findings for empty rules")
	}
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty text")
	}
}
