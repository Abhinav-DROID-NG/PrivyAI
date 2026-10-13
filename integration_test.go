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

	func TestIntegrationContextChangesDecision(t *testing.T) {
		eng, err := privyai.New(privyai.DefaultConfig())
		if err != nil {
			t.Fatalf("failed to initialize engine: %v", err)
		}
		input := "Send alice@example.com"
		external, err := eng.ProcessWithOptions(input, privyai.ProcessOptions{
			ContentType:  privyai.ContentTypePlainText,
			ContextLabel: "external_transmission",
		})
		if err != nil {
			t.Fatal(err)
		}
		local, err := eng.ProcessWithOptions(input, privyai.ProcessOptions{
			ContentType:  privyai.ContentTypePlainText,
			ContextLabel: "local_only",
		})
		if err != nil {
			t.Fatal(err)
		}
		if external.Decision != privyai.ActionRedact || external.Sanitized == input {
			t.Fatalf("external result = %#v", external)
		}
		if local.Decision != privyai.ActionAllow || local.Sanitized != input {
			t.Fatalf("local result = %#v", local)
		}
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

func TestIntegrationPhoneEndToEnd(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Contact customer support at +1-800-555-0199 or (555) 123-4567 for help."
	expected := "Contact customer support at [PHONE_REDACTED] or [PHONE_REDACTED] for help."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized output:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}

	for _, f := range res.Findings {
		if f.Category != "phone" {
			t.Errorf("expected category 'phone', got %q", f.Category)
		}
		if f.Tier != privyai.TierT1Personal {
			t.Errorf("expected TierT1Personal, got %v", f.Tier)
		}
	}
}

func TestIntegrationIPEndToEnd(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Connecting from public 8.8.8.8 to internal 192.168.1.1 and loopback ::1."
	expected := "Connecting from public [IP_REDACTED] to internal [INTERNAL_IP_REDACTED] and loopback [INTERNAL_IP_REDACTED]."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized output:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(res.Findings))
	}

	if res.Findings[0].Category != "ip" || res.Findings[0].Tier != privyai.TierT1Personal {
		t.Errorf("expected public IP at index 0, got: %+v", res.Findings[0])
	}
	if res.Findings[1].Category != "internal_ip" || res.Findings[1].Tier != privyai.TierT2Confidential {
		t.Errorf("expected internal IP at index 1, got: %+v", res.Findings[1])
	}
	if res.Findings[2].Category != "internal_ip" || res.Findings[2].Tier != privyai.TierT2Confidential {
		t.Errorf("expected internal IP at index 2, got: %+v", res.Findings[2])
	}
}

func TestIntegrationMixedEmailPhoneIP(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Email alice@example.com, call +1-800-555-0199, server 10.0.0.1."
	expected := "Email [EMAIL_REDACTED], call [PHONE_REDACTED], server [INTERNAL_IP_REDACTED]."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized output:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	// Idempotence on mixed text
	res2, err := eng.Process(res.Sanitized)
	if err != nil {
		t.Fatalf("idempotence run failed: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Errorf("expected 0 findings on re-run, got %d: %+v", len(res2.Findings), res2.Findings)
	}
	if res2.Sanitized != expected {
		t.Errorf("idempotence sanitized output mismatch: %q", res2.Sanitized)
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

func TestIntegrationSpecExample(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	// Exact requirement from spec:
	// Input: "Send the report to alice@example.com.\nThe service uses API_KEY=sk_example_secret."
	// Expected sanitized output: "Send the report to [EMAIL_REDACTED].\nThe service uses API_KEY=[SECRET_REDACTED]."
	input := "Send the report to alice@example.com.\nThe service uses API_KEY=sk_example_secret."
	expected := "Send the report to [EMAIL_REDACTED].\nThe service uses API_KEY=[SECRET_REDACTED]."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Fatalf("spec example output mismatch:\nexpected:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}

	// Finding 0: email
	if res.Findings[0].Category != "email" || res.Findings[0].Tier != privyai.TierT1Personal {
		t.Errorf("expected email finding at index 0, got: %+v", res.Findings[0])
	}
	// Finding 1: secret
	if res.Findings[1].Category != "secret" || res.Findings[1].Tier != privyai.TierT3Restricted {
		t.Errorf("expected secret finding at index 1, got: %+v", res.Findings[1])
	}

	// Idempotence check on the spec example output
	res2, err := eng.Process(res.Sanitized)
	if err != nil {
		t.Fatalf("idempotence check failed: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Errorf("expected 0 findings from placeholders, got %d: %+v", len(res2.Findings), res2.Findings)
	}
	if res2.Sanitized != expected {
		t.Errorf("idempotence sanitized mismatch: expected %q, got %q", expected, res2.Sanitized)
	}
}

func TestIntegrationSecretsEndToEnd(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Deploy with AWS AKIAIOSFODNN7EXAMPLE and auth Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4m1e_fakeSignatureSegment123 now."
	expected := "Deploy with AWS [AWS_ACCESS_KEY_REDACTED] and auth Bearer [JWT_REDACTED] now."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}

	// Verify privacy: no raw tokens in stats or findings format
	findingsStr := fmt.Sprintf("%+v", res.Findings)
	if strings.Contains(findingsStr, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(findingsStr, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("findings formatted output leaked raw token: %s", findingsStr)
	}
}

func TestIntegrationPEMBlockEndToEnd(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Cert data:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0fakeRSAPrivateKeyData1234567890abcdefghijklmnopqrstuvwxyz\n-----END RSA PRIVATE KEY-----\nEnd of cert."
	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.Blocked || res.Sanitized != "" {
		t.Errorf("expected blocked result with no sanitized output, got blocked=%t sanitized=%q", res.Blocked, res.Sanitized)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Category != "private_key" || res.Findings[0].Tier != privyai.TierT4Critical {
		t.Errorf("expected TierT4Critical private_key, got: %+v", res.Findings[0])
	}
}

func TestIntegrationFinancialEndToEnd(t *testing.T) {
	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Customer paid with card 4111-0000-0000-0008 and transfer to DE89370400440532013000."
	expected := "Customer paid with card [PAYMENT_CARD_REDACTED] and transfer to [IBAN_REDACTED]."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}
	if res.Findings[0].Category != "payment_card" || res.Findings[0].Tier != privyai.TierT3Restricted {
		t.Errorf("expected payment_card T3 at 0, got: %+v", res.Findings[0])
	}
	if res.Findings[1].Category != "iban" || res.Findings[1].Tier != privyai.TierT3Restricted {
		t.Errorf("expected iban T3 at 1, got: %+v", res.Findings[1])
	}
}

func TestIntegrationIdentifiersEndToEnd(t *testing.T) {
	cfg := privyai.DefaultConfig()
	cfg.IdentifierJurisdictions = []string{"US", "UK"}

	eng, err := privyai.New(cfg)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "US tax ID: 123-45-6789 and UK insurance: AB123456A on file."
	expected := "US tax ID: [SSN_REDACTED] and UK insurance: [UK_NINO_REDACTED] on file."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}
}

func TestIntegrationDatabasePasswordOnlyEndToEnd(t *testing.T) {
	cfg := privyai.DefaultConfig()
	cfg.DatabaseRedactMode = privyai.DatabaseRedactPasswordOnly

	eng, err := privyai.New(cfg)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Connect string: postgres://app_user:secret_postgres_pass@db.internal:5432/mydb active."
	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.Blocked || res.Sanitized != "" {
		t.Errorf("expected blocked result with no sanitized output, got blocked=%t sanitized=%q", res.Blocked, res.Sanitized)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Category != "database_credentials" || res.Findings[0].Tier != privyai.TierT4Critical {
		t.Errorf("expected database_credentials T4, got: %+v", res.Findings[0])
	}
}

func TestIntegrationDatabaseFullURLEndToEnd(t *testing.T) {
	cfg := privyai.DefaultConfig()
	cfg.DatabaseRedactMode = privyai.DatabaseRedactFullURL

	eng, err := privyai.New(cfg)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Connect string: postgres://app_user:secret_postgres_pass@db.internal:5432/mydb active."
	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.Blocked || res.Sanitized != "" {
		t.Errorf("expected blocked result with no sanitized output, got blocked=%t sanitized=%q", res.Blocked, res.Sanitized)
	}
}

func TestIntegrationCustomRulesEndToEnd(t *testing.T) {
	cfg := privyai.DefaultConfig()
	cfg.CustomRules = []privyai.CustomRule{
		{
			Name:       "internal_emp",
			Pattern:    `\bEMP-\d{5}\b`,
			Category:   "employee_id",
			Tier:       privyai.TierT2Confidential,
			Confidence: privyai.ConfidenceHigh,
		},
	}

	eng, err := privyai.New(cfg)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	input := "Officer EMP-99881 checked in."
	expected := "Officer [EMPLOYEE_ID_REDACTED] checked in."

	res, err := eng.Process(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Sanitized != expected {
		t.Errorf("expected sanitized:\n%q\ngot:\n%q", expected, res.Sanitized)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Category != "employee_id" || res.Findings[0].Tier != privyai.TierT2Confidential {
		t.Errorf("expected employee_id T2, got: %+v", res.Findings[0])
	}
}
