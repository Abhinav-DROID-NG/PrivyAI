package privyai_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/YOURUSER/privyai"
)

func TestIntegrationEmailEndToEnd(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	// 1. Basic email redaction from spec
	input := "Send the report to alice@example.com."
	expected := "Send the report to [EMAIL_REDACTED]."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized output:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}

	f := res.Findings[0]
	if f.Category != "email" {
		t.Errorf("expected category 'email', got %q", f.Category)
	}
	if f.Start != 19 || f.End != 36 {
		t.Errorf("expected span [19, 36), got [%d, %d)", f.Start, f.End)
	}
	if input[f.Start:f.End] != "alice@example.com" {
		t.Errorf("expected matched span text 'alice@example.com', got %q", input[f.Start:f.End])
	}
	if f.Tier != privyai.TierT1Personal {
		t.Errorf("expected TierT1Personal, got %v", f.Tier)
	}
	if f.Action != privyai.ActionRedact {
		t.Errorf("expected ActionRedact, got %v", f.Action)
	}
	if res.Stats.TotalFindings != 1 {
		t.Errorf("expected TotalFindings 1, got %d", res.Stats.TotalFindings)
	}
	if res.Stats.FindingsByCategory["email"] != 1 {
		t.Errorf("expected 1 email in stats, got %d", res.Stats.FindingsByCategory["email"])
	}
}

func TestIntegrationIdempotence(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Please write to dev@internal.net and support@customer.io."

	res1, err := eng.Process(input)
	if err != nil {
		t.Fatalf("first process failed: %v", err)
	}
	if len(res1.Findings) != 2 {
		t.Fatalf("expected 2 findings in first run, got %d", len(res1.Findings))
	}

	// Re-run on sanitized output
	res2, err := eng.Process(res1.Sanitized)
	if err != nil {
		t.Fatalf("second process failed: %v", err)
	}

	// Idempotence: No new findings must be generated from placeholders
	if len(res2.Findings) != 0 {
		t.Errorf("expected 0 findings on second run, got %d: %+v", len(res2.Findings), res2.Findings)
	}

	if res2.Sanitized != res1.Sanitized {
		t.Errorf("expected identical output on second run, got:\n%q\nvs\n%q", res2.Sanitized, res1.Sanitized)
	}
}

func TestIntegrationDeterminism(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Contact alice@example.com, bob@example.com, and charlie@corp.org today."

	firstResult, err := eng.Process(input)
	if err != nil {
		t.Fatalf("initial process failed: %v", err)
	}

	// Run 100 times and verify identical results
	for i := 0; i < 100; i++ {
		res, err := eng.Process(input)
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		if res.Sanitized != firstResult.Sanitized {
			t.Fatalf("non-deterministic output at iteration %d:\n%q != %q", i, res.Sanitized, firstResult.Sanitized)
		}
		if len(res.Findings) != len(firstResult.Findings) {
			t.Fatalf("non-deterministic findings count at iteration %d", i)
		}
		for j := range res.Findings {
			if res.Findings[j] != firstResult.Findings[j] {
				t.Fatalf("finding mismatch at iter %d finding %d: %+v vs %+v", i, j, res.Findings[j], firstResult.Findings[j])
			}
		}
	}
}

func TestIntegrationUnicodeSafety(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	// Unicode surrounding email: emoji, CJK, accents
	input := "🚀 邮件地址 alice@example.com 很重要！🚀"
	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "🚀 邮件地址 [EMAIL_REDACTED] 很重要！🚀"
	if res.Sanitized != expected {
		t.Errorf("expected %q, got %q", expected, res.Sanitized)
	}
}

func TestIntegrationPrivacyNoSensitiveLeaks(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	sensitiveEmail := "super_secret_user_99@private-corp.com"
	input := fmt.Sprintf("My private email is %s please keep safe.", sensitiveEmail)

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Sanitized must not contain sensitive email
	if strings.Contains(res.Sanitized, sensitiveEmail) {
		t.Fatalf("sanitized text contains raw sensitive email!")
	}

	// 2. Findings struct string representation must never contain sensitive email
	findingsStr := fmt.Sprintf("%+v", res.Findings)
	if strings.Contains(findingsStr, sensitiveEmail) {
		t.Fatalf("findings formatted string leaked raw sensitive email: %s", findingsStr)
	}

	// 3. Stats must not contain sensitive email
	statsStr := fmt.Sprintf("%+v", res.Stats)
	if strings.Contains(statsStr, sensitiveEmail) {
		t.Fatalf("stats leaked raw sensitive email: %s", statsStr)
	}
}

func TestIntegrationConcurrentEngine(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 50; iter++ {
				input := fmt.Sprintf("Worker %d round %d email alice%d@example.com end", id, iter, id)
				res, err := eng.Process(input)
				if err != nil {
					t.Errorf("worker error: %v", err)
				}
				if strings.Contains(res.Sanitized, "@example.com") {
					t.Errorf("worker %d leaked email: %s", id, res.Sanitized)
				}
			}
		}(g)
	}
	wg.Wait()
}
