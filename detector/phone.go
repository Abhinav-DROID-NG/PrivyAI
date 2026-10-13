package detector

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PhoneDetector detects phone numbers in E.164 and standard national formats.
type PhoneDetector struct{}

// NewPhoneDetector creates a new phone detector instance.
func NewPhoneDetector() *PhoneDetector {
	return &PhoneDetector{}
}

// Name returns the identifier of the detector.
func (d *PhoneDetector) Name() string {
	return "phone"
}

// Priority returns the priority of the detector.
func (d *PhoneDetector) Priority() int {
	return 70
}

// Regex matching candidate phone patterns:
// Matches international (+...) or national forms with separators (-, ., space, parentheses).
var phoneCandidateRegex = regexp.MustCompile(`(?:\+\d{1,4}[-.\s]*)?(?:\(\d{1,5}\)[-.\s]*)?(?:\d{1,5}[-.\s]*){2,6}\d{1,5}`)

// Detect scans text and returns candidate phone findings.
func (d *PhoneDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	matches := phoneCandidateRegex.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	var findings []Finding

	for _, match := range matches {
		start, end := match[0], match[1]
		candidate := text[start:end]

		// Clean leading and trailing punctuation (except '+' at start)
		trimmed, trimStart, trimEnd := cleanPhoneCandidate(candidate)
		actualStart := start + trimStart
		actualEnd := start + trimEnd

		if len(trimmed) == 0 {
			continue
		}

		// Boundary check: ensure not embedded in a word or identifier
		if actualStart > 0 {
			prevRune, _ := utf8.DecodeLastRuneInString(text[:actualStart])
			if unicode.IsLetter(prevRune) || prevRune == '_' || prevRune == '/' || prevRune == '@' {
				continue
			}
			if prevRune == '(' && !strings.Contains(trimmed, ")") {
				continue
			}
		}
		if actualEnd < len(text) {
			nextRune, _ := utf8.DecodeRuneInString(text[actualEnd:])
			if unicode.IsLetter(nextRune) || nextRune == '_' || nextRune == '/' || nextRune == '@' {
				continue
			}
		}

		if !isValidPhone(trimmed, text, actualStart, actualEnd) {
			continue
		}

		// Rune boundary verification
		if !utf8.RuneStart(text[actualStart]) || (actualEnd < len(text) && !utf8.RuneStart(text[actualEnd])) {
			continue
		}

		conf := ConfidenceMedium
		if strings.HasPrefix(trimmed, "+") {
			conf = ConfidenceHigh
		}

		findings = append(findings, Finding{
			Category:   "phone",
			Start:      actualStart,
			End:        actualEnd,
			Tier:       TierT1Personal,
			Source:     d.Name(),
			Action:     ActionAllow, // Policy will determine action
			Confidence: conf,
			Validated:  true,
		})
	}

	return findings
}

func cleanPhoneCandidate(s string) (string, int, int) {
	orig := s
	// Strip leading punctuation except '+' and '('
	leadTrim := strings.TrimLeft(s, " \t\r\n.,;:!?-")
	startOffset := len(s) - len(leadTrim)
	s = leadTrim

	// Strip trailing punctuation except ')'
	trailTrim := strings.TrimRight(s, " \t\r\n.,;:!?-")
	endOffset := len(orig) - (len(leadTrim) - len(trailTrim))
	return trailTrim, startOffset, endOffset
}

// Regex for ISO dates YYYY-MM-DD or YYYY/MM/DD
var isoDateRegex = regexp.MustCompile(`^\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b`)

// Regex for timestamps YYYY-MM-DDTHH:MM:SS
var timeRegex = regexp.MustCompile(`^\d{2}:\d{2}(:\d{2})?`)

func isValidPhone(phone, fullText string, start, end int) bool {
	// Must not be a placeholder
	if strings.HasPrefix(phone, "[") && strings.HasSuffix(phone, "_REDACTED]") {
		return false
	}

	// Reject ISO dates (e.g. 2024-01-15)
	if isoDateRegex.MatchString(phone) {
		return false
	}

	// Check if part of a date in context (e.g. 2024-01-15)
	if start >= 5 && fullText[start-5:start-1] == "2024" || (start >= 5 && (strings.HasPrefix(fullText[start-5:], "20") || strings.HasPrefix(fullText[start-5:], "19"))) {
		if fullText[start-1] == '-' || fullText[start-1] == '/' {
			return false
		}
	}

	// Reject timestamps
	if timeRegex.MatchString(phone) {
		return false
	}

	// Count digits and check allowed characters
	digitCount := 0
	separatorCount := 0
	hasPlus := false
	openParen := false
	closeParen := false

	for i, r := range phone {
		if r >= '0' && r <= '9' {
			digitCount++
		} else if r == '+' {
			if i != 0 {
				return false // '+' only allowed as prefix
			}
			hasPlus = true
		} else if r == '(' {
			if openParen {
				return false // at most one opening paren
			}
			openParen = true
		} else if r == ')' {
			if !openParen || closeParen {
				return false // unbalanced paren
			}
			closeParen = true
		} else if r == '-' || r == '.' || r == ' ' {
			separatorCount++
		} else {
			return false // invalid character
		}
	}

	if openParen != closeParen {
		return false // unbalanced parentheses
	}

	// ITU-T E.164: 7 to 15 digits
	if digitCount < 7 || digitCount > 15 {
		return false
	}

	// Reject dot-separated numbers with 3 or 4 segments of 1-3 digits that look like versions or IPs
	// e.g., 1.2.3.4 or 10.0.0.1
	if strings.Count(phone, ".") >= 2 && !strings.Contains(phone, "-") && !hasPlus {
		parts := strings.Split(phone, ".")
		isVersionOrIP := true
		for _, p := range parts {
			if len(p) > 3 || len(p) == 0 {
				isVersionOrIP = false
				break
			}
		}
		if isVersionOrIP {
			return false
		}
	}

	// Reject pure unbroken digits unless E.164 with '+'
	if !hasPlus && separatorCount == 0 {
		// Pure unbroken 7-15 digits without any separator or '+' are IDs or account numbers, not formatted phone
		return false
	}

	return true
}
