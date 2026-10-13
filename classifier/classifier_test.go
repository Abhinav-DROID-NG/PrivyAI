package classifier

import (
	"testing"

	"github.com/YOURUSER/privyai/detector"
)

func TestClassifierMappingAndFallback(t *testing.T) {
	c, err := New(detector.TierT2Confidential, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		category string
		input    detector.Tier
		want     detector.Tier
	}{
		{"email", detector.TierT0Public, detector.TierT1Personal},
		{"internal_ip", detector.TierT0Public, detector.TierT2Confidential},
		{"private_key", detector.TierT0Public, detector.TierT4Critical},
		{"unknown", detector.TierT0Public, detector.TierT2Confidential},
		{"email", detector.TierT3Restricted, detector.TierT3Restricted},
	}
	for _, test := range tests {
		got := c.Classify(detector.Finding{Category: test.category, Tier: test.input}).Tier
		if got != test.want {
			t.Errorf("%s: got %s, want %s", test.category, got, test.want)
		}
	}
}

func TestClassifierOverrideCanLowerTier(t *testing.T) {
	c, err := New(detector.TierT2Confidential, map[string]detector.Tier{"email": detector.TierT0Public})
	if err != nil {
		t.Fatal(err)
	}

	if got := c.Classify(detector.Finding{Category: "email", Tier: detector.TierT3Restricted}).Tier; got != detector.TierT0Public {
		t.Fatalf("got %s, want T0", got)
	}
}

func TestClassifierCustomCategoryKeepsConfiguredTier(t *testing.T) {
	c, err := NewWithCustom(detector.TierT4Critical, nil, map[string]detector.Tier{
		"employee_id": detector.TierT1Personal,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := c.Classify(detector.Finding{Category: "employee_id", Tier: detector.TierT1Personal})
	if got.Tier != detector.TierT1Personal {
		t.Fatalf("got %s, want T1", got.Tier)
	}
}
