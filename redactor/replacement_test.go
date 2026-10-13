package redactor

import (
	"strings"
	"testing"

	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
)

func TestFormatReplacementLabel(t *testing.T) {
	cfg := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyLabel,
	}

	finding := detector.Finding{Category: "email"}
	res := FormatReplacement("alice@example.com", finding, cfg)
	if res != "[EMAIL_REDACTED]" {
		t.Errorf("expected [EMAIL_REDACTED], got %q", res)
	}

	findingSecret := detector.Finding{Category: "aws_access_key"}
	resSecret := FormatReplacement("AKIAIOSFODNN7EXAMPLE", findingSecret, cfg)
	if resSecret != "[AWS_ACCESS_KEY_REDACTED]" {
		t.Errorf("expected [AWS_ACCESS_KEY_REDACTED], got %q", resSecret)
	}
}

func TestFormatReplacementFixedMask(t *testing.T) {
	// Default fixed mask text
	cfg := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyFixedMask,
	}
	finding := detector.Finding{Category: "password"}
	res := FormatReplacement("secret123", finding, cfg)
	if res != "****" {
		t.Errorf("expected '****', got %q", res)
	}

	// Custom fixed mask text
	cfg.FixedMaskText = "[HIDDEN]"
	resCustom := FormatReplacement("secret123", finding, cfg)
	if resCustom != "[HIDDEN]" {
		t.Errorf("expected '[HIDDEN]', got %q", resCustom)
	}
}

func TestFormatReplacementPartialMask(t *testing.T) {
	cfg := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyPartialMask,
		PartialMasks: map[string]PartialMaskConfig{
			"payment_card": {KeepChars: 4, KeepEnd: true, MaskChar: '*'},
			"username":     {KeepChars: 2, KeepEnd: false, MaskChar: '#'},
		},
	}

	// Card: keep last 4
	cardFinding := detector.Finding{Category: "payment_card"}
	resCard := FormatReplacement("4111222233334444", cardFinding, cfg)
	if resCard != "************4444" {
		t.Errorf("expected '************4444', got %q", resCard)
	}

	// Username: keep first 2
	userFinding := detector.Finding{Category: "username"}
	resUser := FormatReplacement("johndoe", userFinding, cfg)
	if resUser != "jo#####" {
		t.Errorf("expected 'jo#####', got %q", resUser)
	}

	// Short text <= KeepChars should fully mask
	shortCard := FormatReplacement("123", cardFinding, cfg)
	if shortCard != "***" {
		t.Errorf("expected fully masked '***', got %q", shortCard)
	}
}

func TestFormatReplacementHMAC(t *testing.T) {
	key := []byte("test-key-32-bytes-long-for-hmac")
	cfg := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyHMAC,
		HMACKey:         key,
		HMACLength:      12,
	}

	finding := detector.Finding{Category: "email"}
	res1 := FormatReplacement("alice@example.com", finding, cfg)
	res2 := FormatReplacement("alice@example.com", finding, cfg)

	// Deterministic
	if res1 != res2 {
		t.Errorf("HMAC replacement not deterministic: %q != %q", res1, res2)
	}
	if !strings.HasPrefix(res1, "[HMAC_") || !strings.HasSuffix(res1, "]") {
		t.Errorf("unexpected HMAC format: %s", res1)
	}
	token := strings.TrimSuffix(strings.TrimPrefix(res1, "[HMAC_"), "]")
	if len(token) != 12 {
		t.Errorf("expected token length 12, got %d (%s)", len(token), token)
	}

	// Without key should fall back to label
	cfgNoKey := ReplacementConfig{
		DefaultStrategy: ReplacementStrategyHMAC,
		HMACKey:         nil,
	}
	resFallback := FormatReplacement("alice@example.com", finding, cfgNoKey)
	if resFallback != "[EMAIL_REDACTED]" {
		t.Errorf("expected fallback to [EMAIL_REDACTED], got %q", resFallback)
	}
}
