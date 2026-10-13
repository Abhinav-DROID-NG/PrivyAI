package detector

import (
	"fmt"
	"regexp"
	"strings"
)

// CustomRule defines a user-specified detection rule.
type CustomRule struct {
	Name            string     `json:"name"`
	Pattern         string     `json:"pattern"`
	Category        string     `json:"category"`
	Tier            Tier       `json:"tier"`
	Confidence      Confidence `json:"confidence"`
	Validator       string     `json:"validator,omitempty"`
	RequiredContext []string   `json:"required_context,omitempty"`
}

type compiledCustomRule struct {
	rule CustomRule
	re   *regexp.Regexp
}

// CustomDetector executes user-defined detection rules compiled at initialization time.
type CustomDetector struct {
	rules []compiledCustomRule
}

// NewCustomDetector compiles and validates custom detection rules.
// Returns an error if any regex pattern is invalid.
func NewCustomDetector(rules []CustomRule) (*CustomDetector, error) {
	var compiled []compiledCustomRule

	for i, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			return nil, fmt.Errorf("%w: custom rule at index %d has empty name", ErrInvalidRule, i)
		}
		if strings.TrimSpace(r.Pattern) == "" {
			return nil, fmt.Errorf("%w: custom rule %q has empty regex pattern", ErrInvalidRule, r.Name)
		}

		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: custom rule %q failed to compile: %v", ErrInvalidRule, r.Name, err)
		}

		category := strings.TrimSpace(r.Category)
		if category == "" {
			category = "custom_" + r.Name
		}

		conf := r.Confidence
		if conf == 0 {
			conf = ConfidenceMedium
		}

		tier := r.Tier
		if !tier.IsValid() {
			tier = TierT2Confidential
		}

		compiled = append(compiled, compiledCustomRule{
			rule: CustomRule{
				Name:            r.Name,
				Pattern:         r.Pattern,
				Category:        category,
				Tier:            tier,
				Confidence:      conf,
				Validator:       strings.ToLower(strings.TrimSpace(r.Validator)),
				RequiredContext: r.RequiredContext,
			},
			re: re,
		})
	}

	return &CustomDetector{
		rules: compiled,
	}, nil
}

// Name returns the identifier of the detector.
func (d *CustomDetector) Name() string {
	return "custom"
}

// Priority returns the priority of the detector.
func (d *CustomDetector) Priority() int {
	return 70
}

// Detect scans input text against all compiled custom rules.
func (d *CustomDetector) Detect(text string) []Finding {
	if len(text) == 0 || len(d.rules) == 0 {
		return nil
	}

	var findings []Finding

	for _, cr := range d.rules {
		matches := cr.re.FindAllStringIndex(text, -1)
		for _, match := range matches {
			start, end := match[0], match[1]
			val := text[start:end]

			if isPlaceholder(val) {
				continue
			}

			// 1. Context validation (if required)
			if len(cr.rule.RequiredContext) > 0 {
				if !hasCustomContext(text, start, end, cr.rule.RequiredContext) {
					continue
				}
			}

			// 2. Custom validator check (if specified)
			validated := false
			if cr.rule.Validator != "" {
				switch cr.rule.Validator {
				case "luhn":
					digits := extractDigits(val)
					if !validateLuhn(digits) {
						continue
					}
					validated = true
				case "mod97":
					cleaned := strings.ToUpper(strings.ReplaceAll(val, " ", ""))
					if !validateIBANMod97(cleaned) {
						continue
					}
					validated = true
				}
			}

			findings = append(findings, Finding{
				Category:   cr.rule.Category,
				Start:      start,
				End:        end,
				Tier:       cr.rule.Tier,
				Source:     cr.rule.Name,
				Action:     ActionAllow,
				Confidence: cr.rule.Confidence,
				Validated:  validated,
			})
		}
	}

	return findings
}

func hasCustomContext(text string, start, end int, contexts []string) bool {
	const windowSize = 50

	wStart := start - windowSize
	if wStart < 0 {
		wStart = 0
	}
	preText := strings.ToLower(text[wStart:start])

	wEnd := end + windowSize
	if wEnd > len(text) {
		wEnd = len(text)
	}
	postText := strings.ToLower(text[end:wEnd])

	for _, c := range contexts {
		cLower := strings.ToLower(strings.TrimSpace(c))
		if cLower != "" && (strings.Contains(preText, cLower) || strings.Contains(postText, cLower)) {
			return true
		}
	}

	return false
}
