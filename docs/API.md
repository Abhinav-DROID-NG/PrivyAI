# API reference

Module path: `github.com/Abhinav-DROID-NG/PrivyAI` (package name `privyai`).

```go
import privyai "github.com/Abhinav-DROID-NG/PrivyAI"
```

The root package is the stable entry point. It aliases the main domain types from the subpackages so ordinary callers import only this one package. For generated, always-current signatures, run `go doc` (for example `go doc -all github.com/Abhinav-DROID-NG/PrivyAI`).

## Contents

- [Engine](#engine)
- [Result and Finding](#result-and-finding)
- [Tier, Action, Confidence](#tier-action-confidence)
- [Process options](#process-options)
- [Config](#config)
- [Errors](#errors)
- [JSON shapes](#json-shapes)
- [Subpackages](#subpackages)

---

## Engine

```go
func New(cfg Config) (*Engine, error)
func (e *Engine) Process(input string) (Result, error)
func (e *Engine) ProcessWithOptions(input string, opts ProcessOptions) (Result, error)
```

`New` validates `cfg`, compiles detectors and custom rules, loads the policy, and returns an engine. The engine is **immutable after construction and safe for concurrent use**; create one and share it.

`Process` inspects plain text with the `external_transmission` context. It is exactly:

```go
e.ProcessWithOptions(input, ProcessOptions{
	ContentType:  ContentTypePlainText,
	ContextLabel: "external_transmission",
})
```

`ProcessWithOptions` selects the content type and context label. **An empty `ContextLabel` is not `external_transmission`.**

Both methods return `(Result, error)`. Always check `error` first; see [Errors](#errors) for the shape of `Result` when `error != nil`.

Processing order: input size check, UTF-8 check, detectors, structured scan, aggregation, classification, policy evaluation, then redaction (or an empty result on `BLOCK`). See [Architecture](architecture.md).

---

## Result and Finding

```go
type Result struct {
	Sanitized          string    `json:"sanitized"`
	Findings           []Finding `json:"findings"`
	Decision           Action    `json:"decision"`
	Blocked            bool      `json:"blocked"`
	Restricted         bool      `json:"restricted"`
	Conditions         []string  `json:"conditions,omitempty"`
	StructuredFallback bool      `json:"structured_fallback,omitempty"`
	Stats              Stats     `json:"stats"`
}

type Stats struct {
	TotalFindings      int            `json:"total_findings"`
	FindingsByCategory map[string]int `json:"findings_by_category"`
	FindingsByTier     map[Tier]int   `json:"findings_by_tier"`
}

type Finding struct {
	Category   string     `json:"category"`
	Start      int        `json:"start"` // inclusive byte offset
	End        int        `json:"end"`   // exclusive byte offset
	Tier       Tier       `json:"tier"`
	Source     string     `json:"source"` // detector name, custom rule name, or structured scanner
	Action     Action     `json:"action"`
	Confidence Confidence `json:"confidence"`
	Validated  bool       `json:"validated"`
}
```

Guarantees and semantics:

- **No raw values.** Neither `Finding`, `Result`, nor any error carries the matched text. `Finding.String()` prints only metadata: `Finding[cat=email span=[5,22) tier=T1 src=email action=REDACT conf=HIGH val=true]`.
- **Offsets are byte offsets** into the original input, half-open `[Start, End)`, and are never rune indexes. They are validated to sit on UTF-8 rune boundaries.
- **`Findings` are sorted** by `Start` ascending and never overlap each other.
- **`Decision`** is the most protective action across findings (`BLOCK` > `RESTRICT` > `REDACT` > `ALLOW`); with no findings it is `ALLOW`.
- **`Blocked`**: `Sanitized` is empty (or `"[REDACTED]"` for a fail-closed error with `FailClosedRedactAll`).
- **`Restricted`**: `Sanitized` still contains `RESTRICT` findings. `Conditions` lists what you must enforce; the engine never enforces them.
- **`StructuredFallback`**: structured parsing failed and the text was scanned normally.
- On a `BLOCK` caused by policy, `Findings` and `Stats` are populated so you can log what triggered it.

---

## Tier, Action, Confidence

All three are integer-backed enums that marshal to and from readable strings.

### Tier

```go
type Tier = detector.Tier

const (
	TierT0Public       // 0
	TierT1Personal     // 1
	TierT2Confidential // 2
	TierT3Restricted   // 3
	TierT4Critical     // 4
)

func ParseTier(s string) (Tier, error)
func (t Tier) String() string  // "T0" ... "T4"
func (t Tier) IsValid() bool
```

`ParseTier` is case-insensitive and accepts `t0`/`0`/`public`/`tier0`, `t1`/`1`/`personal`/`tier1`, `t2`/`2`/`confidential`/`tier2`, `t3`/`3`/`restricted`/`tier3`, `t4`/`4`/`critical`/`tier4`. JSON and text encodings use `"T0"` to `"T4"`; unmarshaling also accepts a bare JSON number.

### Action

```go
type Action = detector.Action

const (
	ActionAllow    // 0
	ActionRedact   // 1
	ActionRestrict // 2
	ActionBlock    // 3
)

func ParseAction(s string) (Action, error)
func MaxAction(a, b Action) Action
func (a Action) String() string // "ALLOW", "REDACT", "RESTRICT", "BLOCK"
func (a Action) MoreSevereThan(other Action) bool
```

### Confidence

```go
type Confidence = detector.Confidence

const (
	ConfidenceLow    // 1
	ConfidenceMedium // 2
	ConfidenceHigh   // 3
)

func ParseConfidence(s string) (Confidence, error) // "LOW", "MEDIUM"/"MED", "HIGH"
func (c Confidence) String() string
```

The zero value of `Confidence` (0) is **not valid** in `Config.CustomRules`.

---

## Process options

```go
type ProcessOptions struct {
	ContentType  ContentType
	ContextLabel string // e.g. "external_transmission", "local_only"
}

type ContentType string

const (
	ContentTypePlainText ContentType = "text/plain"
	ContentTypeJSON      ContentType = "application/json"
	ContentTypeEnv       ContentType = "text/x-env"
	ContentTypeYAMLLines ContentType = "text/x-yaml-lines"
	ContentTypeAuto      ContentType = "auto"
)
```

An unrecognized or empty `ContentType` is treated as plain text. See [Structured data](structured-data.md).

---

## Config

Full field-by-field documentation is in [Configuration](configuration.md). Key points:

```go
func DefaultConfig() Config
func (c Config) Validate() error
```

Related exported types and constants:

```go
type ReplacementStrategy = redactor.ReplacementStrategy
const (
	ReplacementStrategyLabel
	ReplacementStrategyFixedMask
	ReplacementStrategyPartialMask
	ReplacementStrategyHMAC
)

type ReplacementConfig = redactor.ReplacementConfig
type PartialMaskConfig = redactor.PartialMaskConfig

type FailClosedBehavior = redactor.FailClosedBehavior
const (
	FailClosedNoOutput  // Sanitized == ""
	FailClosedRedactAll // Sanitized == "[REDACTED]"
)

type DatabaseRedactMode = detector.DatabaseRedactMode
const (
	DatabaseRedactPasswordOnly
	DatabaseRedactFullURL
)

type CustomRule = detector.CustomRule

const DefaultMaxInputBytes = 10 * 1024 * 1024
```

### Policy aliases

```go
type Policy = policy.Policy
type Rule = policy.Rule
type PolicyReport = policy.Report
type PolicyEvaluation = policy.Evaluation

var LoadPolicy = policy.Load // parse and strictly validate a policy JSON document
```

`Policy.Validate()` returns a `PolicyReport` with non-fatal warnings; see [Policy and tiers](policy-tiers.md#checking-a-policy-for-mistakes).

---

## Errors

Sentinels (use `errors.Is`):

| Error | Returned when |
| --- | --- |
| `ErrInvalidConfig` | `New` rejects the configuration, including malformed policy JSON and `PolicyPath` |
| `ErrHMACKeyRequired` | An HMAC replacement strategy is selected without `Replacement.HMACKey` |
| `ErrInvalidRule` | A custom rule is malformed (the concrete error is `*RuleError`) |
| `ErrInputTooLarge` | `len(input) > MaxInputBytes` |
| `ErrInvalidUTF8` | Input is not valid UTF-8 and `AllowInvalidUTF8` is false |
| `ErrDetectorPanic` | A detector panicked (the concrete error is `*DetectorPanicError`) |
| `ErrInvalidSpan` | A finding span is out of range, misaligned, or overlapping (the concrete error is `*SpanError`) |
| `ErrPolicyConflict` | Declared for unresolvable policy conflicts; the current engine does not return it |

Typed errors (use `errors.As`):

```go
type RuleError struct { RuleIndex int; RuleName string; Reason string }
type DetectorPanicError = detector.DetectorPanicError // DetectorName, Reason
type SpanError = detector.SpanError                   // Start, End, Length, Reason
```

None of these include raw input or matched values.

### What `Result` looks like when `err != nil`

| Failure | `Result` returned |
| --- | --- |
| `ErrInputTooLarge`, `ErrInvalidUTF8`, policy evaluation failure | Fail-closed: `Blocked: true`, `Decision: ActionBlock`, `Sanitized: ""` (or `"[REDACTED]"` with `FailClosedRedactAll`), no findings |
| Detector panic or redaction failure, `FailClosedOnError: true` (default) | Same fail-closed result |
| Detector panic or redaction failure, `FailClosedOnError: false` | Zero `Result{}` (`Decision` is `ActionAllow`) |

In every case, treat a non-nil `error` as "do not transmit the original input".

---

## JSON shapes

`Result`, `Finding`, and `Stats` have JSON tags and can be logged or returned from an API directly (they contain no raw values).

```json
{
  "sanitized": "Send [EMAIL_REDACTED]",
  "findings": [
    {
      "category": "email",
      "start": 5,
      "end": 22,
      "tier": "T1",
      "source": "email",
      "action": "REDACT",
      "confidence": "HIGH",
      "validated": true
    }
  ],
  "decision": "REDACT",
  "blocked": false,
  "restricted": false,
  "stats": {
    "total_findings": 1,
    "findings_by_category": { "email": 1 },
    "findings_by_tier": { "T1": 1 }
  }
}
```

`conditions` and `structured_fallback` are omitted when empty/false. For failure results `findings` and the stats maps are `null`.

---

## Subpackages

The lower-level packages are importable for callers who need custom composition. Most applications only need the root package.

### `detector`

Built-in and custom detection, plus the `Finding` domain type.

```go
type Detector interface {
	Name() string
	Priority() int            // higher wins ties during overlap resolution
	Detect(text string) []Finding
}

func NewEmailDetector() *EmailDetector
func NewPhoneDetector() *PhoneDetector
func NewIPDetector() *IPDetector
func NewSecretsDetector(entropyEnabled bool, entropyThreshold float64) *SecretsDetector
func NewFinancialDetector() *FinancialDetector
func NewIdentifiersDetector(jurisdictions []string) *IdentifiersDetector
func NewDatabaseDetector(mode DatabaseRedactMode) *DatabaseDetector
func NewCustomDetector(rules []CustomRule) (*CustomDetector, error)

// Registry: deterministic ordering (priority desc, then name asc)
func NewRegistry() *Registry
func (r *Registry) Register(d Detector) error // rejects nil, empty name, duplicates
func (r *Registry) Detectors() []Detector
func (r *Registry) Priorities() map[string]int
func (r *Registry) RunAll(text string) ([]Finding, error) // recovers panics
func RunSafe(d Detector, text string) ([]Finding, error)
```

### `classifier`

```go
func New(defaultTier detector.Tier, overrides map[string]detector.Tier) (*Classifier, error)
func NewWithCustom(defaultTier detector.Tier, overrides, custom map[string]detector.Tier) (*Classifier, error)
func (c *Classifier) Classify(f detector.Finding) detector.Finding
func (c *Classifier) ClassifyAll(findings []detector.Finding) []detector.Finding // does not modify its input
func DefaultTierForCategory(category string) (detector.Tier, bool)
```

### `policy`

```go
func Default() Policy                 // the built-in policy
func Load(data []byte) (Policy, error) // strict JSON loader
func LoadDefault() (Policy, error)     // loads the embedded default JSON through Load
var DefaultJSON []byte                 // the embedded default policy document
func (p Policy) Evaluate(f detector.Finding, context string) (Evaluation, error)
func (p Policy) Validate() Report

type Evaluator interface{ Evaluate(detector.Finding, string) (Evaluation, error) }
type EvaluatorFunc func(detector.Finding, string) (Evaluation, error)
func EvaluateFailClosed(e Evaluator, f detector.Finding, context string) (Evaluation, error)
```

### `redactor`

```go
func NewRedactor(cfg ReplacementConfig, failBehavior FailClosedBehavior) *Redactor
func (r *Redactor) Redact(text string, findings []detector.Finding) (string, error)
func ValidateSpans(text string, findings []detector.Finding) error
func FormatReplacement(raw string, f detector.Finding, cfg ReplacementConfig) string
```

`Redact` changes only findings whose `Action` is `ActionRedact`. It requires findings sorted by `Start` and non-overlapping, and validates that before touching the text.

### `structured`

```go
func Scan(input string, format Format, maxDepth int) ([]detector.Finding, bool, error)

const (
	JSON      Format = "json"
	Env       Format = "env"
	YAMLLines Format = "yaml-lines"
)
const DefaultMaxDepth = 100
```

### `internal/findings`

Overlap resolution lives in an `internal` package and cannot be imported from outside this module. See [Extending](extending.md#composing-the-subpackages) for what that means when composing the pieces yourself.
