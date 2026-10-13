package privyai

import (
	"github.com/YOURUSER/privyai/detector"
)

// Tier represents the sensitivity classification of data (T0-T4).
// Tiers express sensitivity only; they do not dictate policy action.
type Tier = detector.Tier

const (
	// TierT0Public represents publicly accessible, non-sensitive data.
	TierT0Public = detector.TierT0Public
	// TierT1Personal represents personal or identifying data requiring selective redaction.
	TierT1Personal = detector.TierT1Personal
	// TierT2Confidential represents confidential data that must be redacted before external transmission.
	TierT2Confidential = detector.TierT2Confidential
	// TierT3Restricted represents highly restricted data such as payment cards, credentials, and government IDs.
	TierT3Restricted = detector.TierT3Restricted
	// TierT4Critical represents critical secrets such as private keys and root database credentials.
	TierT4Critical = detector.TierT4Critical
)

// ParseTier parses a string into a Tier. It is case-insensitive.
var ParseTier = detector.ParseTier

// Action represents an enforcement action decided by policy.
// Severity order: BLOCK > RESTRICT > REDACT > ALLOW.
type Action = detector.Action

const (
	// ActionAllow allows the finding or text through unredacted.
	ActionAllow = detector.ActionAllow
	// ActionRedact redacts the sensitive span.
	ActionRedact = detector.ActionRedact
	// ActionRestrict allows processing only under specific caller-enforced conditions.
	ActionRestrict = detector.ActionRestrict
	// ActionBlock completely blocks transmission or processing of the payload.
	ActionBlock = detector.ActionBlock
)

var (
	// ParseAction parses an action string.
	ParseAction = detector.ParseAction
	// MaxAction returns the more severe of two actions.
	MaxAction = detector.MaxAction
)

// Confidence indicates detection certainty.
type Confidence = detector.Confidence

const (
	// ConfidenceLow indicates a pattern match without syntax validation or context.
	ConfidenceLow = detector.ConfidenceLow
	// ConfidenceMedium indicates a format-validated match or match with supporting context.
	ConfidenceMedium = detector.ConfidenceMedium
	// ConfidenceHigh indicates a checksum-verified match or cryptographically structured token.
	ConfidenceHigh = detector.ConfidenceHigh
)

// ParseConfidence parses a confidence string.
var ParseConfidence = detector.ParseConfidence

// Finding represents metadata about a detected sensitive span.
// In accordance with hard constraints, RAW SENSITIVE VALUES MUST NEVER
// BE STORED IN OR ACCESSIBLE VIA THIS STRUCT.
type Finding = detector.Finding

// Detector defines the interface for sensitive data detectors.
type Detector = detector.Detector

// Stats summarizes findings by count, category, and tier without any raw data.
type Stats struct {
	TotalFindings      int            `json:"total_findings"`
	FindingsByCategory map[string]int `json:"findings_by_category"`
	FindingsByTier     map[Tier]int   `json:"findings_by_tier"`
}

// Result is the deterministic output of processing an input text.
type Result struct {
	Sanitized  string    `json:"sanitized"`
	Findings   []Finding `json:"findings"`
	Decision   Action    `json:"decision"`
	Blocked    bool      `json:"blocked"`
	Restricted bool      `json:"restricted"`
	Conditions []string  `json:"conditions,omitempty"`
	Stats      Stats     `json:"stats"`
}

// ContentType identifies the format or hint of the input text.
type ContentType string

const (
	// ContentTypePlainText is unformatted text.
	ContentTypePlainText ContentType = "text/plain"
	// ContentTypeJSON indicates JSON structured data.
	ContentTypeJSON ContentType = "application/json"
	// ContentTypeEnv indicates KEY=VALUE environment file content.
	ContentTypeEnv ContentType = "text/x-env"
)

// ProcessOptions provides context and options for processing.
type ProcessOptions struct {
	ContentType  ContentType
	ContextLabel string // e.g. "external_transmission", "local_only"
}
