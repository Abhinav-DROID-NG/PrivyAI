package redactor

import (
	"strings"

	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
)

// Redactor applies privacy redactions to text based on findings and replacement configuration.
type Redactor struct {
	cfg          ReplacementConfig
	failBehavior FailClosedBehavior
}

// NewRedactor constructs a new Redactor instance.
func NewRedactor(cfg ReplacementConfig, failBehavior FailClosedBehavior) *Redactor {
	return &Redactor{
		cfg:          cfg,
		failBehavior: failBehavior,
	}
}

// Redact applies replacements to findings whose Action is ActionRedact.
// If any finding has an invalid span or violates rune boundaries, it fails closed according to failBehavior.
func (r *Redactor) Redact(text string, findings []detector.Finding) (string, error) {
	// Filter findings where Action == ActionRedact
	var toRedact []detector.Finding
	for _, f := range findings {
		if f.Action == detector.ActionRedact {
			toRedact = append(toRedact, f)
		}
	}

	if len(toRedact) == 0 {
		return text, nil
	}

	// Validate spans before applying modifications
	if err := ValidateSpans(text, toRedact); err != nil {
		if r.failBehavior == FailClosedRedactAll {
			return "[REDACTED]", err
		}
		return "", err
	}

	// Forward pass redaction using strings.Builder
	var sb strings.Builder
	sb.Grow(len(text))
	lastIdx := 0

	for _, f := range toRedact {
		sb.WriteString(text[lastIdx:f.Start])
		replacement := FormatReplacement(text[f.Start:f.End], f, r.cfg)
		sb.WriteString(replacement)
		lastIdx = f.End
	}
	sb.WriteString(text[lastIdx:])

	return sb.String(), nil
}
