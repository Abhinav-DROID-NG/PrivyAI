package detector

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IPDetector detects IPv4 and IPv6 addresses and classifies them as public or internal.
type IPDetector struct{}

// NewIPDetector creates a new IP detector instance.
func NewIPDetector() *IPDetector {
	return &IPDetector{}
}

// Name returns the detector identifier.
func (d *IPDetector) Name() string {
	return "ip"
}

// Priority returns the priority of the detector.
func (d *IPDetector) Priority() int {
	return 75
}

// Regex matching candidate IPv4 addresses: exactly 4 octets separated by dots.
var ipv4CandidateRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// Regex matching candidate IPv6 addresses.
var ipv6CandidateRegex = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}`)

// Detect scans text and returns findings for IP addresses.
func (d *IPDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	var findings []Finding

	// 1. Scan IPv4 candidates
	v4Matches := ipv4CandidateRegex.FindAllStringIndex(text, -1)
	for _, match := range v4Matches {
		start, end := match[0], match[1]
		candidate := text[start:end]

		// Ensure not preceded or followed by version prefix like 'v' or extra octets
		if start > 0 {
			prevRune, _ := utf8.DecodeLastRuneInString(text[:start])
			if unicode.IsLetter(prevRune) || prevRune == '_' {
				continue
			}
			if prevRune == '.' && start > 1 {
				prevPrev, _ := utf8.DecodeLastRuneInString(text[:start-1])
				if unicode.IsDigit(prevPrev) {
					continue // Extra octet before
				}
			}
		}
		if end < len(text) {
			nextRune, _ := utf8.DecodeRuneInString(text[end:])
			if unicode.IsLetter(nextRune) || nextRune == '_' {
				continue
			}
			if nextRune == '.' && end+1 < len(text) {
				nextNext, _ := utf8.DecodeRuneInString(text[end+1:])
				if unicode.IsDigit(nextNext) {
					continue // Extra octet after (e.g. 1.2.3.4.5)
				}
			}
		}

		if !isValidIPv4(candidate) {
			continue
		}

		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is4() {
			continue
		}

		category, tier := classifyIP(addr)

		findings = append(findings, Finding{
			Category:   category,
			Start:      start,
			End:        end,
			Tier:       tier,
			Source:     d.Name(),
			Action:     ActionAllow,
			Confidence: ConfidenceHigh,
			Validated:  true,
		})
	}

	// 2. Scan IPv6 candidates
	v6Matches := ipv6CandidateRegex.FindAllStringIndex(text, -1)
	for _, match := range v6Matches {
		start, end := match[0], match[1]
		candidate := text[start:end]

		// Ensure not preceded or followed by hex digits or colons
		if start > 0 {
			prevRune, _ := utf8.DecodeLastRuneInString(text[:start])
			if unicode.IsLetter(prevRune) || unicode.IsDigit(prevRune) || prevRune == '_' || prevRune == ':' {
				continue
			}
		}
		if end < len(text) {
			nextRune, _ := utf8.DecodeRuneInString(text[end:])
			if unicode.IsLetter(nextRune) || unicode.IsDigit(nextRune) || nextRune == '_' || nextRune == ':' {
				continue
			}
		}

		// Avoid single-word or short non-IPv6 strings
		if !strings.Contains(candidate, ":") || strings.Count(candidate, ":") < 2 {
			continue
		}

		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is6() {
			continue
		}

		category, tier := classifyIP(addr)

		findings = append(findings, Finding{
			Category:   category,
			Start:      start,
			End:        end,
			Tier:       tier,
			Source:     d.Name(),
			Action:     ActionAllow,
			Confidence: ConfidenceHigh,
			Validated:  true,
		})
	}

	return findings
}

func isValidIPv4(s string) bool {
	// Must not be a placeholder
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "_REDACTED]") {
		return false
	}

	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}

	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}

		// Reject leading zeroes (e.g. "01", "001") except single "0"
		if len(p) > 1 && p[0] == '0' {
			return false
		}

		val, err := strconv.Atoi(p)
		if err != nil || val < 0 || val > 255 {
			return false
		}
	}

	return true
}

func classifyIP(addr netip.Addr) (category string, tier Tier) {
	// Check internal IP ranges:
	// - Private (10/8, 172.16/12, 192.168/16, fc00::/7)
	// - Loopback (127/8, ::1)
	// - Link-local (169.254/16, fe80::/10)
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return "internal_ip", TierT2Confidential
	}

	return "ip", TierT1Personal
}
