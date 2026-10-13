package detector

import (
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SecretsDetector detects credentials, tokens, API keys, PEM blocks, and contextual secrets.
type SecretsDetector struct {
	entropyEnabled   bool
	entropyThreshold float64
}

// NewSecretsDetector creates a new secrets detector.
func NewSecretsDetector(entropyEnabled bool, entropyThreshold float64) *SecretsDetector {
	if entropyThreshold <= 0 {
		entropyThreshold = 4.5
	}
	return &SecretsDetector{
		entropyEnabled:   entropyEnabled,
		entropyThreshold: entropyThreshold,
	}
}

// Name returns the identifier of the detector.
func (d *SecretsDetector) Name() string {
	return "secrets"
}

// Priority returns the priority of the detector.
func (d *SecretsDetector) Priority() int {
	return 90
}

// Regex patterns for known structured tokens.
var (
	// AWS access key ID: AKIA or ASIA followed by 16 alphanumeric characters.
	awsRegex = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)

	// GitHub tokens: classic and fine-grained.
	githubRegex = regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b`)

	// Slack tokens: user, bot, app tokens.
	slackRegex = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)

	// Stripe live/restricted keys.
	stripeRegex = regexp.MustCompile(`\b(sk_live|rk_live)_[A-Za-z0-9]{24,}\b`)

	// Google API keys.
	googleRegex = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)

	// JWT: 3 base64url segments separated by dots, header starting with eyJ.
	jwtRegex = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)

	// PEM private key blocks (RSA, EC, OPENSSH, PGP, etc.).
	pemRegex = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// Contextual key-value pattern:
	// Matches forms: KEY=VALUE, KEY: VALUE, "key": "value", "key"="value"
	// and Authorization: Bearer <token>
	contextualRegex = regexp.MustCompile(`(?i)(?:(?:"|')?(?:password|passwd|pwd|secret|api_key|apikey|token|access_token|auth|bearer|client_secret)(?:"|')?\s*(?:=|:)\s*|Authorization:\s*Bearer\s+)(?:"|')?([^\s"';,}\]]+)(?:"|')?`)
)

// Detect scans text and returns findings for secrets.
func (d *SecretsDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	var findings []Finding

	// 1. Detect PEM Private Keys (Tier T4 Critical)
	for _, match := range pemRegex.FindAllStringIndex(text, -1) {
		start, end := match[0], match[1]
		findings = append(findings, Finding{
			Category:   "private_key",
			Start:      start,
			End:        end,
			Tier:       TierT4Critical,
			Source:     d.Name(),
			Action:     ActionAllow,
			Confidence: ConfidenceHigh,
			Validated:  true,
		})
	}

	// 2. Detect Known Token Formats (Tier T3 Restricted)
	detectTokens := func(re *regexp.Regexp, category string) {
		for _, match := range re.FindAllStringIndex(text, -1) {
			start, end := match[0], match[1]
			val := text[start:end]
			if isPlaceholder(val) {
				continue
			}
			findings = append(findings, Finding{
				Category:   category,
				Start:      start,
				End:        end,
				Tier:       TierT3Restricted,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		}
	}

	detectTokens(awsRegex, "aws_access_key")
	detectTokens(githubRegex, "github_token")
	detectTokens(slackRegex, "slack_token")
	detectTokens(stripeRegex, "stripe_key")
	detectTokens(googleRegex, "google_api_key")
	detectTokens(jwtRegex, "jwt")

	// 3. Detect Contextual Key-Value Secrets (Tier T3 Restricted)
	matches := contextualRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		// match[0], match[1] is the full match (e.g. API_KEY=sk_example_secret)
		// match[2], match[3] is the VALUE submatch group (e.g. sk_example_secret)
		valStart, valEnd := match[2], match[3]
		if valStart < 0 || valEnd <= valStart {
			continue
		}

		val := text[valStart:valEnd]
		if isPlaceholder(val) {
			continue
		}

		// Ensure value has minimum length and is not empty
		if len(val) == 0 {
			continue
		}

		findings = append(findings, Finding{
			Category:   "secret",
			Start:      valStart,
			End:        valEnd,
			Tier:       TierT3Restricted,
			Source:     d.Name(),
			Action:     ActionAllow,
			Confidence: ConfidenceMedium,
			Validated:  true,
		})
	}

	// 4. Optional Entropy Heuristic (if enabled)
	if d.entropyEnabled {
		entropyFindings := d.detectHighEntropy(text)
		findings = append(findings, entropyFindings...)
	}

	return findings
}

func isPlaceholder(s string) bool {
	return strings.HasPrefix(s, "[") && strings.HasSuffix(s, "_REDACTED]")
}

// Regex for hexadecimal strings and UUIDs to exclude from raw entropy
var (
	hexRegex  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	wordRegex = regexp.MustCompile(`\b[A-Za-z0-9_-]{20,}\b`)
)

func (d *SecretsDetector) detectHighEntropy(text string) []Finding {
	matches := wordRegex.FindAllStringIndex(text, -1)
	var findings []Finding

	for _, match := range matches {
		start, end := match[0], match[1]
		word := text[start:end]

		if isPlaceholder(word) {
			continue
		}

		// Exclude pure hex hashes unless in secret context
		if hexRegex.MatchString(word) || uuidRegex.MatchString(word) {
			continue
		}

		// Character-class diversity check: must contain at least 3 distinct character classes
		if !hasCharClassDiversity(word, 3) {
			continue
		}

		entropy := calculateShannonEntropy(word)
		if entropy >= d.entropyThreshold {
			findings = append(findings, Finding{
				Category:   "secret",
				Start:      start,
				End:        end,
				Tier:       TierT3Restricted,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceLow,
				Validated:  false,
			})
		}
	}

	return findings
}

func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	frequencies := make(map[rune]int)
	total := 0
	for _, r := range s {
		frequencies[r]++
		total++
	}

	entropy := 0.0
	for _, count := range frequencies {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func hasCharClassDiversity(s string, minClasses int) bool {
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSpecial {
		classes++
	}

	return classes >= minClasses
}
