// Package structured finds sensitive values in lightweight structured text.
package structured

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/YOURUSER/privyai/detector"
)

// Format identifies the supported structured input form.
type Format string

const (
	// JSON is a JSON document.
	JSON Format = "json"
	// Env is a KEY=VALUE line document.
	Env Format = "env"
	// YAMLLines is the supported key: value line subset.
	YAMLLines Format = "yaml-lines"
)

// DefaultMaxDepth limits recursive JSON nesting.
const DefaultMaxDepth = 100

var sensitiveKeys = map[string]string{
	"password": "secret", "passwd": "secret", "pwd": "secret",
	"secret": "secret", "token": "token", "api_key": "api_key",
	"apikey": "api_key", "access_token": "token", "client_secret": "secret",
	"private_key": "private_key", "ssn": "ssn", "card_number": "payment_card",
	"authorization": "token",
}

// Scan finds forced sensitive-key values and returns whether parsing fell back.
// Returned offsets refer to the original input bytes and exclude JSON quotes.
func Scan(input string, format Format, maxDepth int) ([]detector.Finding, bool, error) {
	switch format {
	case JSON:
		findings, err := scanJSON(input, maxDepth)
		if err != nil {
			return nil, true, nil
		}
		return findings, false, nil
	case Env:
		return scanLines(input, '='), false, nil
	case YAMLLines:
		return scanLines(input, ':'), false, nil
	default:
		return nil, false, fmt.Errorf("unsupported structured format %q", format)
	}
}

type jsonScanner struct {
	text     string
	pos      int
	maxDepth int
	findings []detector.Finding
}

func (s *jsonScanner) skipSpace() {
	for s.pos < len(s.text) {
		switch s.text[s.pos] {
		case ' ', '\t', '\r', '\n':
			s.pos++
		default:
			return
		}
	}
}

func (s *jsonScanner) consume(want byte) bool {
	if s.pos < len(s.text) && s.text[s.pos] == want {
		s.pos++
		return true
	}
	return false
}

func scanJSON(text string, maxDepth int) ([]detector.Finding, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	s := &jsonScanner{text: text, maxDepth: maxDepth}
	s.skipSpace()
	if err := s.value("", 0); err != nil {
		return nil, err
	}
	s.skipSpace()
	if s.pos != len(text) {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return s.findings, nil
}

func (s *jsonScanner) value(key string, depth int) error {
	if depth > s.maxDepth {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	s.skipSpace()
	if s.pos >= len(s.text) {
		return fmt.Errorf("unexpected end of JSON")
	}
	switch s.text[s.pos] {
	case '{':
		return s.object(depth + 1)
	case '[':
		return s.array(depth + 1)
	case '"':
		start, end, decoded, err := s.string()
		if err != nil {
			return err
		}
		s.addFinding(key, start, end, decoded)
		return nil
	default:
		return s.primitive()
	}
}

func (s *jsonScanner) object(depth int) error {
	s.pos++
	s.skipSpace()
	if s.consume('}') {
		return nil
	}
	for {
		s.skipSpace()
		if s.pos >= len(s.text) || s.text[s.pos] != '"' {
			return fmt.Errorf("object key must be a string")
		}
		_, _, key, err := s.string()
		if err != nil {
			return err
		}
		s.skipSpace()
		if !s.consume(':') {
			return fmt.Errorf("object key missing colon")
		}
		if err := s.value(key, depth); err != nil {
			return err
		}
		s.skipSpace()
		if s.consume('}') {
			return nil
		}
		if !s.consume(',') {
			return fmt.Errorf("object missing comma")
		}
	}
}

func (s *jsonScanner) array(depth int) error {
	s.pos++
	s.skipSpace()
	if s.consume(']') {
		return nil
	}
	for {
		if err := s.value("", depth); err != nil {
			return err
		}
		s.skipSpace()
		if s.consume(']') {
			return nil
		}
		if !s.consume(',') {
			return fmt.Errorf("array missing comma")
		}
	}
}

func (s *jsonScanner) primitive() error {
	start := s.pos
	for s.pos < len(s.text) && !strings.ContainsRune(" \t\r\n,]}",
		rune(s.text[s.pos])) {
		s.pos++
	}
	if start == s.pos {
		return fmt.Errorf("invalid JSON value")
	}
	var value any
	if err := json.Unmarshal([]byte(s.text[start:s.pos]), &value); err != nil {
		return err
	}
	return nil
}

func (s *jsonScanner) string() (int, int, string, error) {
	start := s.pos
	s.pos++
	for s.pos < len(s.text) {
		switch s.text[s.pos] {
		case '\\':
			s.pos += 2
		case '"':
			end := s.pos + 1
			raw := s.text[start:end]
			var decoded string
			err := json.Unmarshal([]byte(raw), &decoded)
			s.pos = end
			return start + 1, end - 1, decoded, err
		default:
			s.pos++
		}
	}
	return 0, 0, "", fmt.Errorf("unterminated JSON string")
}

func (s *jsonScanner) addFinding(key string, start, end int, decoded string) {
	category, ok := sensitiveCategory(key)
	if !ok || start == end {
		return
	}
	tier := detector.TierT3Restricted
	if category == "private_key" {
		tier = detector.TierT4Critical
	}
	s.findings = append(s.findings, detector.Finding{
		Category: category, Start: start, End: end, Tier: tier,
		Source: "structured.json", Action: detector.ActionAllow,
		Confidence: detector.ConfidenceHigh, Validated: true,
	})
	_ = decoded
}

func scanLines(input string, separator byte) []detector.Finding {
	var findings []detector.Finding
	offset := 0
	for offset < len(input) {
		end := strings.IndexByte(input[offset:], '\n')
		if end < 0 {
			end = len(input)
		} else {
			end += offset
		}
		line := strings.TrimSuffix(input[offset:end], "\r")
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "export ")
		idx := strings.IndexByte(trimmed, separator)
		if idx >= 0 {
			key := strings.TrimSpace(trimmed[:idx])
			valueStart := idx + 1
			for valueStart < len(trimmed) && unicode.IsSpace(rune(trimmed[valueStart])) {
				valueStart++
			}
			value := strings.TrimSpace(trimmed[valueStart:])
			value = strings.Trim(value, `"'`)
			if category, ok := sensitiveCategory(key); ok && value != "" {
				local := strings.Index(line, value)
				if local >= 0 {
					tier := detector.TierT3Restricted
					if category == "private_key" {
						tier = detector.TierT4Critical
					}
					findings = append(findings, detector.Finding{
						Category: category, Start: offset + local, End: offset + local + len(value),
						Tier: tier, Source: "structured.lines", Action: detector.ActionAllow,
						Confidence: detector.ConfidenceHigh, Validated: true,
					})
				}
			}
		}
		if end == len(input) {
			break
		}
		offset = end + 1
	}
	return findings
}

func sensitiveCategory(key string) (string, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "_", " ", "_").Replace(key)
	if category, ok := sensitiveKeys[key]; ok {
		return category, true
	}
	compact := strings.ReplaceAll(key, "_", "")
	for known, category := range sensitiveKeys {
		if strings.ReplaceAll(known, "_", "") == compact {
			return category, true
		}
	}
	return "", false
}
