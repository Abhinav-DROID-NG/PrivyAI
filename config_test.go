package privyai

import (
	"errors"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() should be valid, got: %v", err)
	}

	if cfg.MaxInputBytes != DefaultMaxInputBytes {
		t.Errorf("expected MaxInputBytes %d, got %d", DefaultMaxInputBytes, cfg.MaxInputBytes)
	}
	if cfg.DefaultTier != TierT2Confidential {
		t.Errorf("expected DefaultTier T2, got %v", cfg.DefaultTier)
	}
	if !cfg.FailClosedOnError {
		t.Error("expected FailClosedOnError to be true by default")
	}

	// ReplacementStrategy String()
	for _, strat := range []ReplacementStrategy{
		ReplacementStrategyLabel,
		ReplacementStrategyFixedMask,
		ReplacementStrategyPartialMask,
		ReplacementStrategyHMAC,
		ReplacementStrategy(99),
	} {
		if strat.String() == "" {
			t.Errorf("empty string representation for %v", strat)
		}
	}
}

func TestConfigValidateMaxInputBytes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxInputBytes = -1
	err := cfg.Validate()
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for negative MaxInputBytes, got: %v", err)
	}
}

func TestConfigValidateDefaultTier(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DefaultTier = Tier(99)
	err := cfg.Validate()
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for out-of-range DefaultTier, got: %v", err)
	}
}

func TestConfigValidateHMACKey(t *testing.T) {
	// Default strategy HMAC without key
	cfg := DefaultConfig()
	cfg.Replacement.DefaultStrategy = ReplacementStrategyHMAC
	cfg.Replacement.HMACKey = nil
	if err := cfg.Validate(); !errors.Is(err, ErrHMACKeyRequired) {
		t.Fatalf("expected ErrHMACKeyRequired, got: %v", err)
	}

	// Category strategy HMAC without key
	cfg = DefaultConfig()
	cfg.Replacement.CategoryStrategies = map[string]ReplacementStrategy{
		"email": ReplacementStrategyHMAC,
	}
	cfg.Replacement.HMACKey = nil
	if err := cfg.Validate(); !errors.Is(err, ErrHMACKeyRequired) {
		t.Fatalf("expected ErrHMACKeyRequired for category strategy, got: %v", err)
	}

	// With key should succeed
	cfg.Replacement.HMACKey = []byte("super-secret-hmac-key")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected validation success with HMAC key, got: %v", err)
	}
}

func TestConfigValidateCustomRules(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(cfg *Config)
		errSubstr string
	}{
		{
			name: "empty rule name",
			modify: func(cfg *Config) {
				cfg.CustomRules = []CustomRule{
					{Name: "", Pattern: `abc`, Category: "test", Tier: TierT1Personal, Confidence: ConfidenceLow},
				}
			},
			errSubstr: "non-empty name",
		},
		{
			name: "empty pattern",
			modify: func(cfg *Config) {
				cfg.CustomRules = []CustomRule{
					{Name: "r1", Pattern: "", Category: "test", Tier: TierT1Personal, Confidence: ConfidenceLow},
				}
			},
			errSubstr: "pattern cannot be empty",
		},
		{
			name: "invalid regex pattern",
			modify: func(cfg *Config) {
				cfg.CustomRules = []CustomRule{
					{Name: "r1", Pattern: `(unclosed`, Category: "test", Tier: TierT1Personal, Confidence: ConfidenceLow},
				}
			},
			errSubstr: "invalid regex",
		},
		{
			name: "empty category",
			modify: func(cfg *Config) {
				cfg.CustomRules = []CustomRule{
					{Name: "r1", Pattern: `abc`, Category: "", Tier: TierT1Personal, Confidence: ConfidenceLow},
				}
			},
			errSubstr: "specify a category",
		},
		{
			name: "invalid tier",
			modify: func(cfg *Config) {
				cfg.CustomRules = []CustomRule{
					{Name: "r1", Pattern: `abc`, Category: "test", Tier: Tier(99), Confidence: ConfidenceLow},
				}
			},
			errSubstr: "invalid tier",
		},
		{
			name: "invalid confidence",
			modify: func(cfg *Config) {
				cfg.CustomRules = []CustomRule{
					{Name: "r1", Pattern: `abc`, Category: "test", Tier: TierT1Personal, Confidence: Confidence(99)},
				}
			},
			errSubstr: "invalid confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
			}
			var ruleErr *RuleError
			if !errors.As(err, &ruleErr) {
				t.Fatalf("expected RuleError, got: %T (%v)", err, err)
			}
			if !errors.Is(err, ErrInvalidRule) {
				t.Errorf("expected errors.Is(err, ErrInvalidRule) to be true, got false")
			}
		})
	}
}
