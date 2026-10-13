package detector

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidValue is returned when parsing a tier, action, or confidence fails.
var ErrInvalidValue = errors.New("privyai: invalid value")

// Tier represents the sensitivity classification of data (T0-T4).
// Tiers express sensitivity only; they do not dictate policy action.
type Tier int

const (
	// TierT0Public represents publicly accessible, non-sensitive data.
	TierT0Public Tier = 0
	// TierT1Personal represents personal or identifying data requiring selective redaction.
	TierT1Personal Tier = 1
	// TierT2Confidential represents confidential data that must be redacted before external transmission.
	TierT2Confidential Tier = 2
	// TierT3Restricted represents highly restricted data such as payment cards, credentials, and government IDs.
	TierT3Restricted Tier = 3
	// TierT4Critical represents critical secrets such as private keys and root database credentials.
	TierT4Critical Tier = 4
)

// String returns the canonical uppercase representation of the tier (e.g. "T0", "T1").
func (t Tier) String() string {
	switch t {
	case TierT0Public:
		return "T0"
	case TierT1Personal:
		return "T1"
	case TierT2Confidential:
		return "T2"
	case TierT3Restricted:
		return "T3"
	case TierT4Critical:
		return "T4"
	default:
		return fmt.Sprintf("Tier(%d)", int(t))
	}
}

// IsValid reports whether t is a valid Tier constant (T0-T4).
func (t Tier) IsValid() bool {
	return t >= TierT0Public && t <= TierT4Critical
}

// ParseTier parses a string into a Tier. It is case-insensitive.
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "t0", "0", "public", "tier0":
		return TierT0Public, nil
	case "t1", "1", "personal", "tier1":
		return TierT1Personal, nil
	case "t2", "2", "confidential", "tier2":
		return TierT2Confidential, nil
	case "t3", "3", "restricted", "tier3":
		return TierT3Restricted, nil
	case "t4", "4", "critical", "tier4":
		return TierT4Critical, nil
	default:
		return -1, fmt.Errorf("%w: unknown tier %q", ErrInvalidValue, s)
	}
}

// MarshalText implements encoding.TextMarshaler.
func (t Tier) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *Tier) UnmarshalText(text []byte) error {
	parsed, err := ParseTier(string(text))
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (t Tier) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Tier) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return t.UnmarshalText([]byte(s))
	}
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		parsed, err := ParseTier(fmt.Sprintf("%d", n))
		if err != nil {
			return err
		}
		*t = parsed
		return nil
	}
	return fmt.Errorf("%w: cannot unmarshal tier from %s", ErrInvalidValue, string(data))
}

// Action represents an enforcement action decided by policy.
// Severity order: BLOCK > RESTRICT > REDACT > ALLOW.
type Action int

const (
	// ActionAllow allows the finding or text through unredacted.
	ActionAllow Action = 0
	// ActionRedact redacts the sensitive span.
	ActionRedact Action = 1
	// ActionRestrict allows processing only under specific caller-enforced conditions.
	ActionRestrict Action = 2
	// ActionBlock completely blocks transmission or processing of the payload.
	ActionBlock Action = 3
)

// String returns the string representation of an Action.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionRedact:
		return "REDACT"
	case ActionRestrict:
		return "RESTRICT"
	case ActionBlock:
		return "BLOCK"
	default:
		return fmt.Sprintf("Action(%d)", int(a))
	}
}

// ParseAction parses an action string in a case-insensitive manner.
func ParseAction(s string) (Action, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ALLOW":
		return ActionAllow, nil
	case "REDACT":
		return ActionRedact, nil
	case "RESTRICT":
		return ActionRestrict, nil
	case "BLOCK":
		return ActionBlock, nil
	default:
		return -1, fmt.Errorf("%w: unknown action %q", ErrInvalidValue, s)
	}
}

// MoreSevereThan returns true if action a is strictly more severe than other.
// Severity ordering is: BLOCK > RESTRICT > REDACT > ALLOW.
func (a Action) MoreSevereThan(other Action) bool {
	return a > other
}

// MaxAction returns the more severe of two actions.
func MaxAction(a, b Action) Action {
	if a >= b {
		return a
	}
	return b
}

// MarshalText implements encoding.TextMarshaler.
func (a Action) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Action) UnmarshalText(text []byte) error {
	parsed, err := ParseAction(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (a Action) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *Action) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return a.UnmarshalText([]byte(s))
}

// Confidence indicates detection certainty.
type Confidence int

const (
	// ConfidenceLow indicates a pattern match without syntax validation or context.
	ConfidenceLow Confidence = 1
	// ConfidenceMedium indicates a format-validated match or match with supporting context.
	ConfidenceMedium Confidence = 2
	// ConfidenceHigh indicates a checksum-verified match (e.g. Luhn, mod-97) or cryptographically structured token.
	ConfidenceHigh Confidence = 3
)

// String returns the canonical string representation of Confidence.
func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "LOW"
	case ConfidenceMedium:
		return "MEDIUM"
	case ConfidenceHigh:
		return "HIGH"
	default:
		return fmt.Sprintf("Confidence(%d)", int(c))
	}
}

// ParseConfidence parses a confidence string.
func ParseConfidence(s string) (Confidence, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return ConfidenceLow, nil
	case "MEDIUM", "MED":
		return ConfidenceMedium, nil
	case "HIGH":
		return ConfidenceHigh, nil
	default:
		return 0, fmt.Errorf("%w: unknown confidence %q", ErrInvalidValue, s)
	}
}

// MarshalText implements encoding.TextMarshaler.
func (c Confidence) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (c *Confidence) UnmarshalText(text []byte) error {
	parsed, err := ParseConfidence(string(text))
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *Confidence) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return c.UnmarshalText([]byte(s))
}

// Finding represents metadata about a detected sensitive span.
// In accordance with hard constraints, RAW SENSITIVE VALUES MUST NEVER
// BE STORED IN OR ACCESSIBLE VIA THIS STRUCT.
type Finding struct {
	Category   string     `json:"category"`
	Start      int        `json:"start"` // Half-open byte offset [Start, End) into original text
	End        int        `json:"end"`   // Half-open byte offset [Start, End) into original text
	Tier       Tier       `json:"tier"`
	Source     string     `json:"source"`
	Action     Action     `json:"action"`
	Confidence Confidence `json:"confidence"`
	Validated  bool       `json:"validated"`
}

// String formats the Finding as a safe metadata string with no sensitive value.
func (f Finding) String() string {
	return fmt.Sprintf("Finding[cat=%s span=[%d,%d) tier=%s src=%s action=%s conf=%s val=%t]",
		f.Category, f.Start, f.End, f.Tier, f.Source, f.Action, f.Confidence, f.Validated)
}
