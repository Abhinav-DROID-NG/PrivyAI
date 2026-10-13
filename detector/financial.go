package detector

import (
	"regexp"
	"strings"
	"unicode"
)

// FinancialDetector detects payment card numbers (Visa, Mastercard, Amex, Discover, etc.)
// and International Bank Account Numbers (IBAN).
type FinancialDetector struct{}

// NewFinancialDetector creates a new financial data detector.
func NewFinancialDetector() *FinancialDetector {
	return &FinancialDetector{}
}

// Name returns the identifier of the detector.
func (d *FinancialDetector) Name() string {
	return "financial"
}

// Priority returns the precedence priority of the detector.
func (d *FinancialDetector) Priority() int {
	return 85
}

// Regular expressions for candidates.
var (
	// Payment card candidates: grouped formats (4-4-4-4, 4-6-5, 4-6-4) or continuous 13-19 digits.
	cardCandidateRegex = regexp.MustCompile(`\b(\d{3,6}(?:[ -]\d{3,6}){2,4}|\d{13,19})\b`)

	// IBAN candidate: 2 country letters + 2 check digits + continuous or 4-char space-separated blocks.
	ibanCandidateRegex = regexp.MustCompile(`\b([A-Z]{2}\d{2}(?:[A-Za-z0-9]{11,30}|(?:\s[A-Za-z0-9]{4}){2,7}(?:\s[A-Za-z0-9]{1,4})?))\b`)
)

// Detect scans the input text for payment cards and IBANs.
func (d *FinancialDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	var findings []Finding

	// 1. Detect Payment Cards
	findings = append(findings, d.detectPaymentCards(text)...)

	// 2. Detect IBANs
	findings = append(findings, d.detectIBANs(text)...)

	return findings
}

func (d *FinancialDetector) detectPaymentCards(text string) []Finding {
	var findings []Finding
	matches := cardCandidateRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		// match[2], match[3] is the capture group for the digits with separators
		start, end := match[2], match[3]
		candidate := text[start:end]

		// Ignore placeholders like [CARD_REDACTED]
		if isPlaceholder(candidate) {
			continue
		}

		// Reject if adjacent to dots (e.g. IP addresses or version strings like 1.2.3.4.5)
		if start > 0 && text[start-1] == '.' {
			continue
		}
		if end < len(text) && text[end] == '.' {
			// Check if part of dot-separated version
			if end+1 < len(text) && unicode.IsDigit(rune(text[end+1])) {
				continue
			}
		}

		// Extract digits only
		digits := extractDigits(candidate)
		n := len(digits)
		if n < 13 || n > 19 {
			continue
		}

		// Known card brand length and prefix validation
		if !isValidCardIssuer(digits) {
			continue
		}

		// Luhn checksum validation
		if !validateLuhn(digits) {
			continue
		}

		findings = append(findings, Finding{
			Category:   "payment_card",
			Start:      start,
			End:        end,
			Tier:       TierT3Restricted,
			Source:     d.Name(),
			Action:     ActionAllow,
			Confidence: ConfidenceHigh,
			Validated:  true,
		})
	}

	return findings
}

func (d *FinancialDetector) detectIBANs(text string) []Finding {
	var findings []Finding
	matches := ibanCandidateRegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		start, end := match[2], match[3]
		rawIBAN := text[start:end]

		// Clean spaces
		cleaned := strings.ToUpper(strings.ReplaceAll(rawIBAN, " ", ""))
		if len(cleaned) < 15 || len(cleaned) > 34 {
			continue
		}

		// Validate country length
		if !isValidIBANCountryLength(cleaned) {
			continue
		}

		// Validate MOD-97 (ISO 7064)
		if !validateIBANMod97(cleaned) {
			continue
		}

		findings = append(findings, Finding{
			Category:   "iban",
			Start:      start,
			End:        end,
			Tier:       TierT3Restricted,
			Source:     d.Name(),
			Action:     ActionAllow,
			Confidence: ConfidenceHigh,
			Validated:  true,
		})
	}

	return findings
}

func extractDigits(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// validateLuhn verifies the Luhn checksum (mod-10).
func validateLuhn(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// isValidCardIssuer checks standard card brand prefix and length requirements.
func isValidCardIssuer(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}

	// Visa: begins with 4, length 13, 16, or 19
	if strings.HasPrefix(digits, "4") {
		return n == 13 || n == 16 || n == 19
	}

	// Mastercard: 51-55 or 2221-2720, length 16
	if n == 16 {
		if len(digits) >= 2 {
			p2 := digits[:2]
			if p2 >= "51" && p2 <= "55" {
				return true
			}
		}
		if len(digits) >= 4 {
			p4 := digits[:4]
			if p4 >= "2221" && p4 <= "2720" {
				return true
			}
		}
	}

	// American Express: 34 or 37, length 15
	if n == 15 && (strings.HasPrefix(digits, "34") || strings.HasPrefix(digits, "37")) {
		return true
	}

	// Discover: 6011, 622126-622925, 644-649, 65, length 16 or 19
	if n == 16 || n == 19 {
		if strings.HasPrefix(digits, "6011") || strings.HasPrefix(digits, "65") {
			return true
		}
		if len(digits) >= 3 {
			p3 := digits[:3]
			if p3 >= "644" && p3 <= "649" {
				return true
			}
		}
		if len(digits) >= 6 {
			p6 := digits[:6]
			if p6 >= "622126" && p6 <= "622925" {
				return true
			}
		}
	}

	// Diners Club: 300-305, 36, 38, length 14
	if n == 14 {
		if strings.HasPrefix(digits, "36") || strings.HasPrefix(digits, "38") {
			return true
		}
		if len(digits) >= 3 {
			p3 := digits[:3]
			if p3 >= "300" && p3 <= "305" {
				return true
			}
		}
	}

	// JCB: 3528-3589, length 16
	if n == 16 && len(digits) >= 4 {
		p4 := digits[:4]
		if p4 >= "3528" && p4 <= "3589" {
			return true
		}
	}

	return false
}

// ISO 13616 standard IBAN lengths by country code.
var ibanCountryLengths = map[string]int{
	"AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16,
	"BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24,
	"DK": 18, "DO": 28, "EE": 20, "FO": 18, "FI": 18, "FR": 27, "GE": 22,
	"DE": 22, "GI": 23, "GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26,
	"IE": 22, "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "KW": 30, "LV": 21,
	"LB": 28, "LI": 21, "LT": 20, "LU": 20, "MK": 19, "MT": 31, "MR": 27,
	"MU": 30, "MC": 27, "MD": 24, "ME": 22, "NL": 18, "NO": 15, "PK": 24,
	"PS": 29, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "SM": 27, "SA": 24,
	"RS": 22, "SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21, "TN": 24,
	"TR": 26, "AE": 23, "GB": 22, "VG": 24,
}

func isValidIBANCountryLength(iban string) bool {
	if len(iban) < 4 {
		return false
	}
	country := iban[:2]
	expectedLen, ok := ibanCountryLengths[country]
	if !ok {
		// If country not in strict table, require standard length range [15, 34]
		return len(iban) >= 15 && len(iban) <= 34
	}
	return len(iban) == expectedLen
}

// validateIBANMod97 implements ISO 7064 MOD-97-10 check.
func validateIBANMod97(iban string) bool {
	if len(iban) < 4 {
		return false
	}

	// 1. Move first 4 characters to the back: BBAN + CountryCode + CheckDigits
	rearranged := iban[4:] + iban[:4]

	// 2. Calculate mod 97 chunk-by-chunk by expanding letters A-Z -> 10-35
	rem := 0
	for _, ch := range rearranged {
		if unicode.IsDigit(ch) {
			rem = (rem*10 + int(ch-'0')) % 97
		} else if ch >= 'A' && ch <= 'Z' {
			num := int(ch-'A') + 10
			// Process two digits: num / 10 and num % 10
			rem = (rem*10 + num/10) % 97
			rem = (rem*10 + num%10) % 97
		} else {
			return false
		}
	}

	return rem == 1
}
