package privyai

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestTierStringAndParse(t *testing.T) {
	tests := []struct {
		tier     Tier
		expected string
		aliases  []string
	}{
		{TierT0Public, "T0", []string{"t0", "0", "public", "tier0", "PUBLIC"}},
		{TierT1Personal, "T1", []string{"t1", "1", "personal", "tier1", "PERSONAL"}},
		{TierT2Confidential, "T2", []string{"t2", "2", "confidential", "tier2", "CONFIDENTIAL"}},
		{TierT3Restricted, "T3", []string{"t3", "3", "restricted", "tier3", "RESTRICTED"}},
		{TierT4Critical, "T4", []string{"t4", "4", "critical", "tier4", "CRITICAL"}},
	}

	for _, tt := range tests {
		if tt.tier.String() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.tier.String())
		}

		for _, alias := range tt.aliases {
			parsed, err := ParseTier(alias)
			if err != nil {
				t.Fatalf("unexpected error parsing %q: %v", alias, err)
			}
			if parsed != tt.tier {
				t.Errorf("parsing %q: expected %v, got %v", alias, tt.tier, parsed)
			}
		}
	}

	// Unknown tier
	if _, err := ParseTier("T99"); err == nil {
		t.Error("expected error for unknown tier, got nil")
	}

	// Out of bounds string
	outOfBounds := Tier(99)
	if outOfBounds.String() != "Tier(99)" {
		t.Errorf("expected Tier(99), got %s", outOfBounds.String())
	}
}

func TestTierJSON(t *testing.T) {
	type wrapper struct {
		T Tier `json:"tier"`
	}

	w := wrapper{T: TierT3Restricted}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("failed to marshal tier: %v", err)
	}

	var decoded wrapper
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal tier: %v", err)
	}

	if decoded.T != TierT3Restricted {
		t.Errorf("expected T3, got %v", decoded.T)
	}

	// Unmarshal from integer in JSON
	intJSON := []byte(`{"tier": 4}`)
	if err := json.Unmarshal(intJSON, &decoded); err != nil {
		t.Fatalf("failed to unmarshal integer tier: %v", err)
	}
	if decoded.T != TierT4Critical {
		t.Errorf("expected T4, got %v", decoded.T)
	}

	// Unmarshal invalid JSON
	invalidJSON := []byte(`{"tier": "invalid"}`)
	if err := json.Unmarshal(invalidJSON, &decoded); err == nil {
		t.Error("expected error for invalid tier JSON, got nil")
	}
}

func TestActionStringAndParse(t *testing.T) {
	tests := []struct {
		action   Action
		expected string
		aliases  []string
	}{
		{ActionAllow, "ALLOW", []string{"allow", "ALLOW", "Allow"}},
		{ActionRedact, "REDACT", []string{"redact", "REDACT", "Redact"}},
		{ActionRestrict, "RESTRICT", []string{"restrict", "RESTRICT", "Restrict"}},
		{ActionBlock, "BLOCK", []string{"block", "BLOCK", "Block"}},
	}

	for _, tt := range tests {
		if tt.action.String() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.action.String())
		}

		for _, alias := range tt.aliases {
			parsed, err := ParseAction(alias)
			if err != nil {
				t.Fatalf("unexpected error parsing %q: %v", alias, err)
			}
			if parsed != tt.action {
				t.Errorf("parsing %q: expected %v, got %v", alias, tt.action, parsed)
			}
		}
	}

	// Unknown action
	if _, err := ParseAction("IGNORE"); err == nil {
		t.Error("expected error for unknown action, got nil")
	}

	// Out of bounds string
	outOfBounds := Action(99)
	if outOfBounds.String() != "Action(99)" {
		t.Errorf("expected Action(99), got %s", outOfBounds.String())
	}
}

func TestActionSeverity(t *testing.T) {
	// Ordering: BLOCK > RESTRICT > REDACT > ALLOW
	if !ActionBlock.MoreSevereThan(ActionRestrict) {
		t.Error("expected BLOCK > RESTRICT")
	}
	if !ActionRestrict.MoreSevereThan(ActionRedact) {
		t.Error("expected RESTRICT > REDACT")
	}
	if !ActionRedact.MoreSevereThan(ActionAllow) {
		t.Error("expected REDACT > ALLOW")
	}
	if ActionAllow.MoreSevereThan(ActionBlock) {
		t.Error("ALLOW should not be more severe than BLOCK")
	}

	if MaxAction(ActionAllow, ActionRedact) != ActionRedact {
		t.Error("expected MaxAction(ALLOW, REDACT) == REDACT")
	}
	if MaxAction(ActionBlock, ActionRestrict) != ActionBlock {
		t.Error("expected MaxAction(BLOCK, RESTRICT) == BLOCK")
	}
}

func TestActionJSON(t *testing.T) {
	type wrapper struct {
		A Action `json:"action"`
	}

	w := wrapper{A: ActionBlock}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("failed to marshal action: %v", err)
	}

	var decoded wrapper
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal action: %v", err)
	}

	if decoded.A != ActionBlock {
		t.Errorf("expected BLOCK, got %v", decoded.A)
	}

	// Invalid
	if err := json.Unmarshal([]byte(`{"action": "invalid"}`), &decoded); err == nil {
		t.Error("expected error for invalid action JSON, got nil")
	}
}

func TestConfidence(t *testing.T) {
	tests := []struct {
		conf     Confidence
		expected string
		aliases  []string
	}{
		{ConfidenceLow, "LOW", []string{"low", "LOW"}},
		{ConfidenceMedium, "MEDIUM", []string{"medium", "MEDIUM", "med", "Med"}},
		{ConfidenceHigh, "HIGH", []string{"high", "HIGH"}},
	}

	for _, tt := range tests {
		if tt.conf.String() != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.conf.String())
		}
		for _, alias := range tt.aliases {
			parsed, err := ParseConfidence(alias)
			if err != nil {
				t.Fatalf("unexpected error parsing %q: %v", alias, err)
			}
			if parsed != tt.conf {
				t.Errorf("parsing %q: expected %v, got %v", alias, tt.conf, parsed)
			}
		}
	}

	if _, err := ParseConfidence("UNKNOWN"); err == nil {
		t.Error("expected error for unknown confidence, got nil")
	}

	outOfBounds := Confidence(99)
	if outOfBounds.String() != "Confidence(99)" {
		t.Errorf("expected Confidence(99), got %s", outOfBounds.String())
	}

	type wrapper struct {
		C Confidence `json:"confidence"`
	}
	w := wrapper{C: ConfidenceHigh}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded wrapper
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.C != ConfidenceHigh {
		t.Errorf("expected HIGH, got %v", decoded.C)
	}
	if err := json.Unmarshal([]byte(`{"confidence": "bogus"}`), &decoded); err == nil {
		t.Error("expected error for invalid confidence json")
	}
}

func TestFindingFormatDoesNotContainRawText(t *testing.T) {
	f := Finding{
		Category:   "aws_access_key",
		Start:      10,
		End:        30,
		Tier:       TierT3Restricted,
		Source:     "secrets",
		Action:     ActionRedact,
		Confidence: ConfidenceHigh,
		Validated:  true,
	}

	formatted := f.String()
	// Must contain metadata
	if formatted == "" {
		t.Fatal("formatted finding is empty")
	}
	// Verify it contains expected metadata labels
	expectedSubstrings := []string{"cat=aws_access_key", "span=[10,30)", "tier=T3", "src=secrets", "action=REDACT", "conf=HIGH", "val=true"}
	for _, sub := range expectedSubstrings {
		if !contains(formatted, sub) {
			t.Errorf("expected finding format to contain %q, got: %s", sub, formatted)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && errors.New(s) != nil && testSubstr(s, substr)))
}

func testSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
