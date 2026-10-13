package privyai_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Abhinav-DROID-NG/PrivyAI"
)

func FuzzProcess(f *testing.F) {
	// Seed corpus
	f.Add("Contact alice@example.com for help")
	f.Add("No emails here 1234567890")
	f.Add("<admin@domain.co.uk> [EMAIL_REDACTED]")
	f.Add("")
	f.Add("🚀 unicode test with email 邮箱: user@server.org end 🌟")
	f.Add("email.with.dots@sub.domain.com. Trailing period.")
	f.Add("Multi-line\nalice@test.com\r\nbob@test.com\n")
	f.Add(strings.Repeat("a", 100) + "@domain.com")
	f.Add("The service uses API_KEY=sk_example_secret.")
	f.Add("AWS key AKIAIOSFODNN7EXAMPLE active")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----")
	f.Add("Contact +1-800-555-0199 and 192.168.1.1")

	eng, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		f.Fatalf("failed to create engine: %v", err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		res, err := eng.Process(input)
		if err != nil {
			// Expected errors: ErrInputTooLarge or ErrInvalidUTF8
			return
		}

		// 1. Valid UTF-8 input must produce valid UTF-8 output
		if utf8.ValidString(input) && !utf8.ValidString(res.Sanitized) {
			t.Fatalf("sanitized output is not valid UTF-8 for valid UTF-8 input")
		}

		// 2. Validate findings invariants
		textLen := len(input)
		prevEnd := -1
		for i, finding := range res.Findings {
			if finding.Start < 0 || finding.Start >= finding.End || finding.End > textLen {
				t.Fatalf("finding %d span [%d, %d) out of bounds for text length %d", i, finding.Start, finding.End, textLen)
			}
			if !utf8.RuneStart(input[finding.Start]) {
				t.Fatalf("finding %d start %d not on rune boundary", i, finding.Start)
			}
			if finding.End < textLen && !utf8.RuneStart(input[finding.End]) {
				t.Fatalf("finding %d end %d not on rune boundary", i, finding.End)
			}
			if finding.Start < prevEnd {
				t.Fatalf("finding %d overlaps with previous finding (prevEnd=%d)", i, prevEnd)
			}
			prevEnd = finding.End
		}

		// 3. Idempotence: re-processing sanitized output should never flag placeholders
		res2, err2 := eng.Process(res.Sanitized)
		if err2 == nil {
			for _, f2 := range res2.Findings {
				spanText := res.Sanitized[f2.Start:f2.End]
				if strings.Contains(spanText, "_REDACTED") {
					t.Fatalf("idempotence failure: placeholder flagged as finding: %s", spanText)
				}
			}
		}
	})
}
