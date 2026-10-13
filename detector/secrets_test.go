package detector

import (
	"testing"
)

func TestSecretsDetectorKnownTokens(t *testing.T) {
	d := NewSecretsDetector(false, 4.5)

	tests := []struct {
		name             string
		input            string
		expectedSpanText string
		expectedCategory string
		expectedTier     Tier
	}{
		{
			name:             "AWS Access Key",
			input:            "AWS key: AKIAIOSFODNN7EXAMPLE active",
			expectedSpanText: "AKIAIOSFODNN7EXAMPLE",
			expectedCategory: "aws_access_key",
			expectedTier:     TierT3Restricted,
		},
		{
			name:             "GitHub Classic Token",
			input:            "Use " + "ghp_" + "fakeGitHubClassicToken1234567890abcdefg to push",
			expectedSpanText: "ghp_" + "fakeGitHubClassicToken1234567890abcdefg",
			expectedCategory: "github_token",
			expectedTier:     TierT3Restricted,
		},
		{
			name:             "Slack Token",
			input:            "Bot token " + "xoxb-" + "1234567890-abcdefghijk configured",
			expectedSpanText: "xoxb-" + "1234567890-abcdefghijk",
			expectedCategory: "slack_token",
			expectedTier:     TierT3Restricted,
		},
		{
			name:             "Stripe Live Key",
			input:            "Stripe " + "sk_live_" + "fakeStripeSecretKey1234567890 ready",
			expectedSpanText: "sk_live_" + "fakeStripeSecretKey1234567890",
			expectedCategory: "stripe_key",
			expectedTier:     TierT3Restricted,
		},
		{
			name:             "Google API Key",
			input:            "Maps key " + "AIza" + "SyFakeGoogleApiKey1234567890abcdef here",
			expectedSpanText: "AIza" + "SyFakeGoogleApiKey1234567890abcdef",
			expectedCategory: "google_api_key",
			expectedTier:     TierT3Restricted,
		},
		{
			name:             "JWT Token",
			input:            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4m1e_fakeSignatureSegment123",
			expectedSpanText: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4m1e_fakeSignatureSegment123",
			expectedCategory: "jwt",
			expectedTier:     TierT3Restricted,
		},
		{
			name: "PEM RSA Private Key",
			input: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0fakeRSAPrivateKeyData1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`,
			expectedSpanText: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0fakeRSAPrivateKeyData1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`,
			expectedCategory: "private_key",
			expectedTier:     TierT4Critical,
		},
		{
			name: "PEM OPENSSH Private Key",
			input: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----`,
			expectedSpanText: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----`,
			expectedCategory: "private_key",
			expectedTier:     TierT4Critical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected finding in %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expectedSpanText {
				t.Errorf("expected matched span %q, got %q", tt.expectedSpanText, matched)
			}
			if f.Category != tt.expectedCategory {
				t.Errorf("expected category %q, got %q", tt.expectedCategory, f.Category)
			}
			if f.Tier != tt.expectedTier {
				t.Errorf("expected tier %v, got %v", tt.expectedTier, f.Tier)
			}
		})
	}
}

func TestSecretsDetectorContextualKeyValue(t *testing.T) {
	d := NewSecretsDetector(false, 4.5)

	tests := []struct {
		name              string
		input             string
		expectedValueSpan string
	}{
		{
			name:              "API_KEY assignment from spec",
			input:             "The service uses API_KEY=sk_example_secret.",
			expectedValueSpan: "sk_example_secret",
		},
		{
			name:              "password with quotes",
			input:             `database password="MySecretPassword123!"`,
			expectedValueSpan: "MySecretPassword123!",
		},
		{
			name:              "token with colon",
			input:             "access_token: token_val_987654321",
			expectedValueSpan: "token_val_987654321",
		},
		{
			name:              "JSON key value",
			input:             `{"client_secret": "secret_abc_123"}`,
			expectedValueSpan: "secret_abc_123",
		},
		{
			name:              "Authorization Bearer header",
			input:             "Authorization: Bearer header_token_abc_xyz",
			expectedValueSpan: "header_token_abc_xyz",
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
			if matched != tt.expectedValueSpan {
				t.Errorf("expected value span %q, got %q", tt.expectedValueSpan, matched)
			}
			if f.Category != "secret" {
				t.Errorf("expected category 'secret', got %q", f.Category)
			}
			if f.Tier != TierT3Restricted {
				t.Errorf("expected TierT3Restricted, got %v", f.Tier)
			}
		})
	}
}

func TestSecretsDetectorEntropy(t *testing.T) {
	// 1. Off by default
	dOff := NewSecretsDetector(false, 4.5)
	highEntropyText := "random string aX8#mK9$vL2@pQ5!wE1%tR7&"
	if len(dOff.Detect(highEntropyText)) != 0 {
		t.Error("expected 0 findings when entropy is off")
	}

	// 2. On with threshold
	dOn := NewSecretsDetector(true, 4.0)
	// Candidate: length >= 20, character diversity >= 3 classes, high Shannon entropy
	candidate := "aK9#mP2$xL7@vQ4!wR8%tZ"
	input := "Random token: " + candidate
	findings := dOn.Detect(input)
	if len(findings) == 0 {
		t.Fatalf("expected entropy detection finding in %q", input)
	}

	// 3. Exclude pure hex hashes and UUIDs
	gitCommitSHA := "Commit is 4b825dc642cb6eb9a060e54bf8d69288fbee4904 in git"
	if len(dOn.Detect(gitCommitSHA)) != 0 {
		t.Errorf("pure hex commit hash should be excluded from entropy findings")
	}

	uuidStr := "Resource id 123e4567-e89b-12d3-a456-426614174000 created"
	if len(dOn.Detect(uuidStr)) != 0 {
		t.Errorf("UUID should be excluded from entropy findings")
	}
}

func TestSecretsDetectorNegative(t *testing.T) {
	d := NewSecretsDetector(false, 4.5)

	negatives := []string{
		"Clean text with no credentials or secrets",
		"Just the word password in documentation without assignment",
		"Discussing token architecture in RFC",
		"Unterminated PEM block -----BEGIN RSA PRIVATE KEY----- without end",
		"Placeholder [SECRET_REDACTED]",
		"Placeholder [AWS_ACCESS_KEY_REDACTED]",
		"Placeholder [PRIVATE_KEY_REDACTED]",
		"Normal short word secret",
		"Too short AWS key AKIA123",
		"Invalid stripe key sk_test_too_short",
		"Random text with numbers 1234567890",
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

func TestSecretsDetectorEdgeCases(t *testing.T) {
	d := NewSecretsDetector(false, 4.5)

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// Secret at start of string
	inputStart := "API_KEY=sk_example_secret is loaded"
	findingsStart := d.Detect(inputStart)
	if len(findingsStart) != 1 {
		t.Fatalf("expected 1 finding at start: %+v", findingsStart)
	}
	if inputStart[findingsStart[0].Start:findingsStart[0].End] != "sk_example_secret" {
		t.Errorf("expected span text sk_example_secret, got: %s", inputStart[findingsStart[0].Start:findingsStart[0].End])
	}

	// Secret at end of string
	inputEnd := "Config: API_KEY=sk_example_secret"
	findingsEnd := d.Detect(inputEnd)
	if len(findingsEnd) != 1 {
		t.Fatalf("expected 1 finding at end: %+v", findingsEnd)
	}
	if inputEnd[findingsEnd[0].Start:findingsEnd[0].End] != "sk_example_secret" {
		t.Errorf("expected span text sk_example_secret, got: %s", inputEnd[findingsEnd[0].Start:findingsEnd[0].End])
	}
}

func FuzzSecretsDetector(f *testing.F) {
	f.Add("API_KEY=sk_example_secret")
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----")
	f.Add("[SECRET_REDACTED]")
	f.Add("Clean text without credentials")

	d := NewSecretsDetector(true, 4.5)
	f.Fuzz(func(t *testing.T, text string) {
		findings := d.Detect(text)
		for _, finding := range findings {
			if finding.Start < 0 || finding.Start >= finding.End || finding.End > len(text) {
				t.Fatalf("invalid secrets span [%d, %d) for text length %d", finding.Start, finding.End, len(text))
			}
		}
	})
}
