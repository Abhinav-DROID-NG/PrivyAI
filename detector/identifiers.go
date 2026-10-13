package detector

import (
	"regexp"
	"strings"
)

// IdentifiersDetector detects government-issued identifiers based on configured jurisdictions.
type IdentifiersDetector struct {
	jurisdictions map[string]bool
}

// NewIdentifiersDetector creates an identifiers detector for specified jurisdictions (e.g. "US", "UK").
// Defaults to ["US"] if jurisdictions is empty.
func NewIdentifiersDetector(jurisdictions []string) *IdentifiersDetector {
	if len(jurisdictions) == 0 {
		jurisdictions = []string{"US"}
	}

	jm := make(map[string]bool)
	for _, j := range jurisdictions {
		jm[strings.ToUpper(strings.TrimSpace(j))] = true
	}

	return &IdentifiersDetector{
		jurisdictions: jm,
	}
}

// Name returns the identifier of the detector.
func (d *IdentifiersDetector) Name() string {
	return "identifiers"
}

// Priority returns the priority of the detector.
func (d *IdentifiersDetector) Priority() int {
	return 80
}

var (
	// Formatted US SSN: AAA-GG-SSSS or AAA GG SSSS
	usSSNFormattedRegex = regexp.MustCompile(`\b(\d{3})[- ](\d{2})[- ](\d{4})\b`)

	// Unformatted US SSN: 9 digits
	usSSNUnformattedRegex = regexp.MustCompile(`\b(\d{9})\b`)

	// UK NINO: 2 letters, 6 digits, 1 letter suffix (A-D)
	ukNINORegex = regexp.MustCompile(`(?i)\b([A-Z]{2})\s*(\d{2})\s*(\d{2})\s*(\d{2})\s*([A-D])\b`)

	// Context keywords required for unformatted SSN detection
	ssnContextRegex = regexp.MustCompile(`(?i)\b(ssn|social\s+security|social\s+ins|tax\s*id|taxpayer\s*id|tin)\b`)
)

// Detect scans input text for government identifiers in active jurisdictions.
func (d *IdentifiersDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	var findings []Finding

	// US Jurisdiction (SSN)
	if d.jurisdictions["US"] {
		findings = append(findings, d.detectUSSSN(text)...)
	}

	// UK Jurisdiction (NINO)
	if d.jurisdictions["UK"] || d.jurisdictions["GB"] {
		findings = append(findings, d.detectUKNINO(text)...)
	}

	return findings
}

func (d *IdentifiersDetector) detectUSSSN(text string) []Finding {
	var findings []Finding

	// 1. Formatted SSN: AAA-GG-SSSS or AAA GG SSSS
	formattedMatches := usSSNFormattedRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range formattedMatches {
		if len(match) < 8 {
			continue
		}
		start, end := match[0], match[1]
		val := text[start:end]

		if isPlaceholder(val) {
			continue
		}

		area := text[match[2]:match[3]]
		group := text[match[4]:match[5]]
		serial := text[match[6]:match[7]]

		if isValidSSN(area, group, serial) {
			findings = append(findings, Finding{
				Category:   "ssn",
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

	// 2. Unformatted SSN: 9 digits (requires surrounding context keywords)
	unformattedMatches := usSSNUnformattedRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range unformattedMatches {
		if len(match) < 4 {
			continue
		}
		start, end := match[0], match[1]
		val := text[start:end]

		if isPlaceholder(val) {
			continue
		}

		area := val[0:3]
		group := val[3:5]
		serial := val[5:9]

		if !isValidSSN(area, group, serial) {
			continue
		}

		// Require SSN context in preceding or succeeding text window
		if hasSSNContext(text, start, end) {
			findings = append(findings, Finding{
				Category:   "ssn",
				Start:      start,
				End:        end,
				Tier:       TierT3Restricted,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceMedium,
				Validated:  true,
			})
		}
	}

	return findings
}

func isValidSSN(area, group, serial string) bool {
	// Area rules:
	// - Cannot be "000"
	// - Cannot be "666"
	// - Cannot be in range 900-999
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}

	// Group rules:
	// - Cannot be "00"
	if group == "00" {
		return false
	}

	// Serial rules:
	// - Cannot be "0000"
	if serial == "0000" {
		return false
	}

	return true
}

func hasSSNContext(text string, start, end int) bool {
	const windowSize = 50

	// Check window before
	wStart := start - windowSize
	if wStart < 0 {
		wStart = 0
	}
	preText := text[wStart:start]
	if ssnContextRegex.MatchString(preText) {
		return true
	}

	// Check window after
	wEnd := end + windowSize
	if wEnd > len(text) {
		wEnd = len(text)
	}
	postText := text[end:wEnd]
	return ssnContextRegex.MatchString(postText)
}

func (d *IdentifiersDetector) detectUKNINO(text string) []Finding {
	var findings []Finding
	matches := ukNINORegex.FindAllStringSubmatchIndex(text, -1)

	for _, match := range matches {
		if len(match) < 12 {
			continue
		}
		start, end := match[0], match[1]
		val := text[start:end]

		if isPlaceholder(val) {
			continue
		}

		prefix := strings.ToUpper(text[match[2]:match[3]])
		suffix := strings.ToUpper(text[match[10]:match[11]])

		if isValidUKNINO(prefix, suffix) {
			findings = append(findings, Finding{
				Category:   "uk_nino",
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

	return findings
}

func isValidUKNINO(prefix, suffix string) bool {
	if len(prefix) != 2 || len(suffix) != 1 {
		return false
	}

	// Characters D, F, I, Q, U, V are not used as either of the first two letters.
	// Letter O is not used as the second letter.
	disallowedFirst := "DFIQUV"
	disallowedSecond := "DFIOQUV"

	if strings.ContainsRune(disallowedFirst, rune(prefix[0])) {
		return false
	}
	if strings.ContainsRune(disallowedSecond, rune(prefix[1])) {
		return false
	}

	// Disallowed prefix combinations
	disallowedPrefixes := map[string]bool{
		"BG": true, "GB": true, "KN": true, "NK": true,
		"NT": true, "TN": true, "ZZ": true,
	}
	if disallowedPrefixes[prefix] {
		return false
	}

	// Suffix must be A, B, C, or D
	s := rune(suffix[0])
	if s != 'A' && s != 'B' && s != 'C' && s != 'D' {
		return false
	}

	return true
}
