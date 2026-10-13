package detector

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// EmailDetector detects RFC-5322 subset email addresses.
type EmailDetector struct{}

// NewEmailDetector creates a new email detector instance.
func NewEmailDetector() *EmailDetector {
	return &EmailDetector{}
}

// Name returns the identifier of the detector.
func (d *EmailDetector) Name() string {
	return "email"
}

// Priority returns the priority of the detector.
func (d *EmailDetector) Priority() int {
	return 80
}

// Regex to capture candidate email patterns.
// Local part allows alphanumeric plus ._%+- (no consecutive or leading/trailing dots verified in post-check).
// Domain part allows alphanumeric, hyphen, dot.
var emailCandidateRegex = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)

// Detect scans text and returns candidate email findings.
func (d *EmailDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	matches := emailCandidateRegex.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding

	for _, match := range matches {
		start, end := match[0], match[1]
		candidate := text[start:end]

		// Trim any accidental trailing punctuation that regex might have grabbed
		trimmedCandidate, trimStart, trimEnd := cleanCandidate(candidate)
		actualStart := start + trimStart
		actualEnd := start + trimEnd

		// Reject if immediately preceded by characters that would form an invalid email prefix
		if actualStart > 0 {
			prev := text[actualStart-1]
			if prev == '.' || prev == '@' || prev == '%' || prev == '+' || prev == '_' || prev == '-' {
				continue
			}
		}

		if !isValidEmail(trimmedCandidate) {
			continue
		}

		// Ensure start and end are on valid rune boundaries
		if !utf8.RuneStart(text[actualStart]) || (actualEnd < len(text) && !utf8.RuneStart(text[actualEnd])) {
			continue
		}

		findings = append(findings, Finding{
			Category:   "email",
			Start:      actualStart,
			End:        actualEnd,
			Tier:       TierT1Personal,
			Source:     d.Name(),
			Action:     ActionAllow, // Policy will assign Action
			Confidence: ConfidenceHigh,
			Validated:  true,
		})
	}

	return findings
}

func cleanCandidate(s string) (cleaned string, startOffset int, endOffset int) {
	orig := s
	// Strip leading characters that are not valid local part beginnings
	leadTrim := strings.TrimLeft(s, "<>\"'()[]{}.,;:!?")
	startOffset = len(s) - len(leadTrim)
	s = leadTrim

	// Strip trailing punctuation
	trailTrim := strings.TrimRight(s, "<>\"'()[]{}.,;:!?")
	endOffset = len(orig) - (len(leadTrim) - len(trailTrim))
	cleaned = trailTrim
	return cleaned, startOffset, endOffset
}

func isValidEmail(email string) bool {
	// Must not be a redaction placeholder
	if strings.HasPrefix(email, "[") && strings.HasSuffix(email, "_REDACTED]") {
		return false
	}

	// Must contain exactly one '@'
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local := parts[0]
	domain := parts[1]

	// Non-empty checks
	if len(local) == 0 || len(domain) == 0 {
		return false
	}

	// Length limits: local <= 64, domain <= 255, total <= 254 (RFC 5321)
	if len(local) > 64 || len(domain) > 255 || len(email) > 254 {
		return false
	}

	// Local part checks: no leading or trailing dot, no consecutive dots
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}

	// Domain checks: no leading or trailing dot, no consecutive dots
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}

	domainLabels := strings.Split(domain, ".")
	if len(domainLabels) < 2 {
		return false
	}

	for _, label := range domainLabels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}

	// TLD check: last label must be at least 2 chars and only letters
	tld := domainLabels[len(domainLabels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		c := tld[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}

	return true
}
