package detector

import (
	"regexp"
)

// DatabaseRedactMode specifies whether to redact only the password component or the entire connection string.
type DatabaseRedactMode int

const (
	// DatabaseRedactPasswordOnly redacts only the password component in connection strings.
	DatabaseRedactPasswordOnly DatabaseRedactMode = 0
	// DatabaseRedactFullURL redacts the entire connection URI or string.
	DatabaseRedactFullURL DatabaseRedactMode = 1
)

// DatabaseDetector detects database connection strings with embedded credentials.
type DatabaseDetector struct {
	mode DatabaseRedactMode
}

// NewDatabaseDetector creates a new database connection credentials detector.
func NewDatabaseDetector(mode DatabaseRedactMode) *DatabaseDetector {
	return &DatabaseDetector{
		mode: mode,
	}
}

// Name returns the identifier of the detector.
func (d *DatabaseDetector) Name() string {
	return "database"
}

// Priority returns the priority of the detector.
// Higher than generic secrets (90) so DB URLs are handled with appropriate mode.
func (d *DatabaseDetector) Priority() int {
	return 95
}

var (
	// URL connection strings with embedded credentials:
	// Matches: scheme://[user[:password]@]host[:port][/path][?query]
	// Submatches:
	// 1: full URL
	// 2: user (if user:pass)
	// 3: password (if user:pass)
	// 4: user (if user only)
	dbURLRegex = regexp.MustCompile(`(?i)\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps)://(?:([^:@\s/]+):([^@\s/]+)@|([^@\s/]+)@)?([^\s"'<>;]+))\b`)

	// ADO / OLEDB / Key-Value connection strings containing credentials:
	// Looks for patterns containing Server/Data Source AND Password/Pwd on the same line
	dbKeyValueRegex = regexp.MustCompile(`(?i)\b(?:Server|Data\s+Source|Database|Initial\s+Catalog|Host)\s*=[^;\r\n]+;[^\r\n]*?(?:Password|Pwd)\s*=\s*([^;\r\n"'\s]+)`)

	// Alternative order: Password/Pwd first, followed by Server/Data Source/Database on the same line
	dbKeyValueReverseRegex = regexp.MustCompile(`(?i)\b(?:Password|Pwd)\s*=\s*([^;\r\n"'\s]+);[^\r\n]*?(?:Server|Data\s+Source|Database|Initial\s+Catalog|Host)\s*=[^;\r\n]+`)

	// JDBC URL with credentials in query: jdbc:postgresql://host:port/db?user=...&password=...
	jdbcRegex = regexp.MustCompile(`(?i)\b(jdbc:(?:postgresql|mysql|oracle|sqlserver|mariadb)://[^\s"'<>;]+?(?:password|pwd)=([^\s&"'<>;]+)[^\s"'<>;]*)\b`)
)

// Detect scans input text for database connection strings and embedded credentials.
func (d *DatabaseDetector) Detect(text string) []Finding {
	if len(text) == 0 {
		return nil
	}

	var findings []Finding

	// 1. URL-based connection strings (postgres://, mysql://, mongodb://, redis://, amqp://)
	urlMatches := dbURLRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range urlMatches {
		if len(match) < 12 {
			continue
		}

		fullStart, fullEnd := match[2], match[3]
		passStart, passEnd := match[6], match[7]

		// Only match when credentials are present in the URL
		if passStart < 0 || passEnd <= passStart {
			continue
		}

		passVal := text[passStart:passEnd]
		if isPlaceholder(passVal) || isPlaceholder(text[fullStart:fullEnd]) {
			continue
		}

		if d.mode == DatabaseRedactFullURL {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      fullStart,
				End:        fullEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		} else {
			// DatabaseRedactPasswordOnly
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      passStart,
				End:        passEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		}
	}

	// 2. ADO / Key-Value connection strings
	kvMatches := dbKeyValueRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range kvMatches {
		if len(match) < 4 {
			continue
		}
		fullStart, fullEnd := match[0], match[1]
		passStart, passEnd := match[2], match[3]

		passVal := text[passStart:passEnd]
		if isPlaceholder(passVal) || isPlaceholder(text[fullStart:fullEnd]) {
			continue
		}

		if d.mode == DatabaseRedactFullURL {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      fullStart,
				End:        fullEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		} else {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      passStart,
				End:        passEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		}
	}

	// Reverse key-value order (Password=...; Server=...)
	kvRevMatches := dbKeyValueReverseRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range kvRevMatches {
		if len(match) < 4 {
			continue
		}
		fullStart, fullEnd := match[0], match[1]
		passStart, passEnd := match[2], match[3]

		passVal := text[passStart:passEnd]
		if isPlaceholder(passVal) || isPlaceholder(text[fullStart:fullEnd]) {
			continue
		}

		if d.mode == DatabaseRedactFullURL {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      fullStart,
				End:        fullEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		} else {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      passStart,
				End:        passEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		}
	}

	// 3. JDBC connection strings with embedded credentials
	jdbcMatches := jdbcRegex.FindAllStringSubmatchIndex(text, -1)
	for _, match := range jdbcMatches {
		if len(match) < 6 {
			continue
		}
		fullStart, fullEnd := match[2], match[3]
		passStart, passEnd := match[4], match[5]

		passVal := text[passStart:passEnd]
		if isPlaceholder(passVal) || isPlaceholder(text[fullStart:fullEnd]) {
			continue
		}

		if d.mode == DatabaseRedactFullURL {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      fullStart,
				End:        fullEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		} else {
			findings = append(findings, Finding{
				Category:   "database_credentials",
				Start:      passStart,
				End:        passEnd,
				Tier:       TierT4Critical,
				Source:     d.Name(),
				Action:     ActionAllow,
				Confidence: ConfidenceHigh,
				Validated:  true,
			})
		}
	}

	return findings
}
