# Extending PrivyAI

There are four ways to adapt PrivyAI, from lightest to heaviest:

1. [Custom rules](#custom-rules): add regex detectors through `Config`
2. [Tier overrides and policy](#tier-overrides-and-policy): change how findings are judged and handled
3. [Replacement strategies](#replacement-strategies): change what redacted text looks like
4. [Composing the subpackages](#composing-the-subpackages): build your own pipeline with a custom `Detector`

Most needs are met by 1 to 3.

---

## Custom rules

A custom rule is a Go (RE2) regular expression plus the metadata to treat its matches like any built-in finding. Rules are compiled once in `privyai.New`; a bad rule fails fast with a `*RuleError`.

```go
cfg := privyai.DefaultConfig()
cfg.CustomRules = []privyai.CustomRule{
	{
		Name:       "internal-host",
		Pattern:    `\b[a-z0-9-]+\.corp\.example\.com\b`,
		Category:   "internal_hostname",
		Tier:       privyai.TierT2Confidential,
		Confidence: privyai.ConfidenceHigh,
	},
}
engine, err := privyai.New(cfg)

res, _ := engine.Process("ssh build01.corp.example.com now")
// ssh [INTERNAL_HOSTNAME_REDACTED] now
// res.Findings[0].Source == "internal-host"
```

Field summary (full details in [Configuration](configuration.md#custom-rules)):

| Field | Required | Notes |
| --- | --- | --- |
| `Name` | yes | Appears as `Finding.Source` |
| `Pattern` | yes | The whole match becomes the finding span |
| `Category` | yes | Drives the redaction label (`[INTERNAL_HOSTNAME_REDACTED]`) and policy matching |
| `Tier` | set it | The zero value is T0, which the default policy allows unredacted |
| `Confidence` | yes | `ConfidenceLow`, `ConfidenceMedium`, or `ConfidenceHigh` |
| `Validator` | no | `"luhn"` or `"mod97"` |
| `RequiredContext` | no | Words that must appear near the match |

### Tips for writing patterns

- **Anchor your pattern.** Use `\b` or specific delimiters. The matched text *is* the span, so an unanchored `\d{8}` will also match inside longer numbers and inside identifiers like `ABC-12345678`.
- **Go's `regexp` is RE2:** no lookahead, lookbehind, or backreferences. In exchange, matching time is linear in the input, so a custom rule cannot trigger catastrophic backtracking.
- **Test with synthetic data only**, including near-misses your pattern should *not* match.

### Validators

`Validator: "luhn"` keeps a match only if its digits pass the Luhn checksum; `"mod97"` applies the IBAN MOD-97 check. They cut false positives for numeric formats:

```go
privyai.CustomRule{
	Name: "loyalty-card", Pattern: `\b\d{16}\b`, Category: "loyalty_card",
	Tier: privyai.TierT3Restricted, Confidence: privyai.ConfidenceHigh,
	Validator: "luhn",
}
// "1234567812345678" fails Luhn: not flagged.
```

When a custom rule and a built-in detector flag the *same span at the same tier* (for example, a Luhn-valid number that is also a real card), the built-in finding is the one reported.

### Required context

`RequiredContext` drops matches unless one of the listed words appears (case-insensitive, substring) in the text **within 50 bytes before or after** the match.

```go
privyai.CustomRule{
	Name: "acct", Pattern: `\b\d{8}\b`, Category: "account_number",
	Tier: privyai.TierT3Restricted, Confidence: privyai.ConfidenceMedium,
	RequiredContext: []string{"account", "acct"},
}
```

The window is generous. In `cust ABC-12345678 acct 55512345 order 11122233`, **all three** eight-digit runs are flagged because `acct` is within 50 bytes of each. Context keeps rules out of unrelated documents; it does not tie a keyword to one specific number. Combine it with a tighter pattern when that matters, for example `(?i)acct\s+\d{8}` or `\bacct\s+(\d{8})\b` for a match that includes the keyword.

---

## Tier overrides and policy

**Change a category's tier** with `Config.TierOverrides` (can raise or lower):

```go
cfg.TierOverrides = map[string]privyai.Tier{
	"phone": privyai.TierT2Confidential, // always redact phones, even for local_only
}
```

**Change what happens to a tier or category** with `Config.PolicyJSON`:

```go
cfg.PolicyJSON = []byte(`{
  "rules": [
    {"id":"block-cards","category":"payment_card","action":"BLOCK"},
    {"id":"t1-redact","min_tier":"T1","max_tier":"T1","action":"REDACT"},
    {"id":"t2-redact","min_tier":"T2","max_tier":"T2","action":"REDACT"},
    {"id":"t3-redact","min_tier":"T3","max_tier":"T3","action":"REDACT"},
    {"id":"t4-block","min_tier":"T4","max_tier":"T4","action":"BLOCK"}
  ]
}`)
```

Remember to cover every tier you can produce (including your custom categories' tiers); a finding that matches no rule fails closed. Full rules in [Policy and tiers](policy-tiers.md).

---

## Replacement strategies

Per-category replacement is configured in `Config.Replacement`. Combine strategies freely:

```go
cfg.Replacement.DefaultStrategy = privyai.ReplacementStrategyLabel
cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{
	"payment_card": privyai.ReplacementStrategyPartialMask, // ***************1111
	"email":        privyai.ReplacementStrategyHMAC,        // [HMAC_…]
	"ssn":          privyai.ReplacementStrategyFixedMask,   // ****
}
cfg.Replacement.HMACKey = key
```

See [Configuration](configuration.md#replacement).

---

## Composing the subpackages

The root engine runs a fixed set of built-in detectors plus `CustomRules`. It has **no hook for registering your own `Detector` implementation.** If regex isn't enough (you need a lookup table, a parser, or an external classification), build a pipeline from the lower-level packages:

```go
package main

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/Abhinav-DROID-NG/PrivyAI/classifier"
	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
	"github.com/Abhinav-DROID-NG/PrivyAI/policy"
	"github.com/Abhinav-DROID-NG/PrivyAI/redactor"
)

// ticketDetector implements detector.Detector.
type ticketDetector struct{}

func (ticketDetector) Name() string  { return "ticket" }
func (ticketDetector) Priority() int { return 60 }

var ticketRe = regexp.MustCompile(`\bTKT-\d{5}\b`)

func (ticketDetector) Detect(text string) []detector.Finding {
	var out []detector.Finding
	for _, m := range ticketRe.FindAllStringIndex(text, -1) {
		out = append(out, detector.Finding{
			Category:   "ticket",
			Start:      m[0],
			End:        m[1],
			Tier:       detector.TierT2Confidential,
			Source:     "ticket",
			Confidence: detector.ConfidenceMedium,
		})
	}
	return out
}

func main() {
	text := "Ticket TKT-12345 from alice@example.com"

	// 1. Detect.
	reg := detector.NewRegistry()
	_ = reg.Register(detector.NewEmailDetector())
	_ = reg.Register(ticketDetector{})
	found, err := reg.RunAll(text)
	if err != nil {
		panic(err) // fail closed in real code
	}

	// 2. Order and de-overlap. The redactor requires findings sorted by Start
	//    and non-overlapping. The engine's resolver is internal, so you own this.
	sort.Slice(found, func(i, j int) bool { return found[i].Start < found[j].Start })

	// 3. Classify.
	cls, _ := classifier.New(detector.TierT2Confidential, nil)
	found = cls.ClassifyAll(found)

	// 4. Apply policy.
	pol := policy.Default()
	for i := range found {
		ev, _ := policy.EvaluateFailClosed(pol, found[i], "external_transmission")
		found[i].Action = ev.Action
	}

	// 5. Redact.
	red := redactor.NewRedactor(
		redactor.ReplacementConfig{DefaultStrategy: redactor.ReplacementStrategyLabel},
		redactor.FailClosedNoOutput,
	)
	out, err := red.Redact(text, found)
	fmt.Println(out, err)
	// Ticket [TICKET_REDACTED] from [EMAIL_REDACTED] <nil>
}
```

Things to know when composing:

- **Overlap resolution is not exported.** The engine's aggregation step lives in `internal/findings`. `redactor.Redact` validates its input and returns a span error if findings overlap or are out of order, so if your detectors can overlap, drop or merge the overlapping findings yourself. (Policy in [Architecture](architecture.md#aggregation) describes the rules the engine uses, if you want to mirror them.)
- **The decision is yours to combine.** Take the most severe action across findings with `detector.MaxAction`, and return nothing if it is `ActionBlock`. `redactor.Redact` only changes `ActionRedact` findings; it never blocks.
- **Detector contract.** Return findings with byte offsets `[Start, End)` on UTF-8 rune boundaries; set `Action` to `ActionAllow` and let policy decide; never store the matched text in a finding; skip text that is already a redaction placeholder if you want idempotent output. Calls should be safe for concurrent use.
- **Fail closed.** `Registry.RunAll` recovers detector panics into a `*DetectorPanicError`. Treat any error as "do not transmit".

If you would rather have your detector inside `privyai.Engine`, that is a change to the library itself; see [Adding a built-in detector](development.md#adding-a-built-in-detector).
